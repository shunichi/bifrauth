//! bifrauthd verifier core (P4 core).
//!
//! The root-owned verifier's state machine: issue challenges from a trusted PAM context, keep pending
//! requests with a CLOCK_BOOTTIME deadline, and verify iPhone responses (design §9.7, §15.3, §16, §11).
//!
//! This module is a library with no socket/IPC. The root Unix socket IPC (SO_PEERCRED, framing, the
//! confirmation-code notification) lives in [`session`]/[`serve`]; the admin CLI is the `bifrauthctl`
//! binary, which drives [`registry`]. It builds on [`bifrauth_proto`] and [`bifrauth_crypto`].
//!
//! Trust model: the verifier is the sole source of truth. The TTL authority is `CLOCK_BOOTTIME`
//! (suspend-inclusive), not the wall clock. The response's `signed_payload_hash` is recomputed and never
//! used as a signature input; the P-256 signature is verified against the stored canonical bytes.
//!
//! Concurrency: all mutation goes through `&mut self`, so within this core the consume-then-verify step is
//! atomic. The IPC layer serializes only these short state transitions (issue / cancel / verify) under a
//! mutex and releases it during socket and transport I/O (see [`session`]).
//!
//! Device registry: the persistent, root-owned store lives in [`registry`]; this core holds an in-memory
//! copy for verification. Revocation is a one-way tombstone: a revoked device stays known (so a re-register
//! is refused, design §14.2) but fails verification ([`VerifyError::RevokedDevice`], design §9.7/§18.3).
//! The daemon loads a validated point-in-time [`DeviceSnapshot`] and installs it atomically via
//! [`Verifier::replace_devices`] (task 0009).

pub mod registry;
pub mod resolver;
pub mod serve;
pub mod session;
pub mod systemd;

#[cfg(test)]
mod e2e_tests;

use bifrauth_crypto as crypto;
pub use bifrauth_ipc::{BoottimeClock, Clock};
use bifrauth_proto::{Challenge, Envelope, Response, SchemaError};
use std::collections::HashMap;

/// Maximum total pending requests across all uids (design §15.3 queue cap).
pub const MAX_PENDING_TOTAL: usize = 256;
/// Maximum concurrent pending requests for a single uid (design §15.3).
pub const MAX_PENDING_PER_UID: usize = 8;
/// How many times to regenerate a colliding request_id before giving up (astronomically unlikely).
const MAX_REQUEST_ID_TRIES: u32 = 8;

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
    /// The device is registered but revoked (design §9.7 step 11, §18.3). Distinguished from
    /// `UnregisteredDevice` for audit/observability; both consume the request and deny.
    RevokedDevice,
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
    /// A revoked (tombstoned) registration also counts as already registered (design §14.2: an old
    /// key is not silently re-trusted).
    AlreadyRegistered,
}

/// Errors from [`Verifier::revoke_device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeError {
    /// No registration exists for this (uid, device_id).
    NotRegistered,
    /// The registration is already revoked (revocation is one-way; idempotent callers can ignore this).
    AlreadyRevoked,
}

/// Errors from building or installing a [`DeviceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// A device's stored bytes do not parse as a P-256 SEC1 public key.
    InvalidPublicKey,
    /// The same (uid, device_id) appeared twice in the snapshot.
    Duplicate,
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

/// A registered device: its P-256 SEC1 public key and whether it has been revoked (tombstone).
#[derive(Debug, Clone)]
struct DeviceEntry {
    sec1: Vec<u8>,
    revoked: bool,
}

/// The in-memory device map: uid -> (iphone_device_id -> entry).
type DeviceMap = HashMap<u32, HashMap<[u8; 16], DeviceEntry>>;

/// A validated, point-in-time set of device registrations, ready to install into a [`Verifier`] with
/// [`Verifier::replace_devices`]. Constructed only via [`DeviceSnapshot::builder`], which validates every
/// public key and rejects a duplicate (uid, device_id); the private field makes the validated invariant a
/// type guarantee, so a caller cannot inject an unvalidated registry. See task 0009 plan D4-a.
#[derive(Debug, Clone, Default)]
pub struct DeviceSnapshot {
    devices: DeviceMap,
}

/// Accumulates device records into a [`DeviceSnapshot`], validating as it goes.
#[derive(Debug, Default)]
pub struct DeviceSnapshotBuilder {
    devices: DeviceMap,
}

impl DeviceSnapshot {
    /// Start building a snapshot.
    pub fn builder() -> DeviceSnapshotBuilder {
        DeviceSnapshotBuilder::default()
    }

    /// Total number of device registrations (across all uids) in this snapshot.
    pub fn len(&self) -> usize {
        self.devices.values().map(|m| m.len()).sum()
    }

    /// Whether the snapshot holds no registrations.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DeviceSnapshotBuilder {
    /// Add one device. The SEC1 bytes are validated as a P-256 public key; a repeated (uid, device_id)
    /// is rejected (the registry stores one file per pair, so a duplicate signals corruption).
    pub fn add(
        &mut self,
        uid: u32,
        device_id: [u8; 16],
        p256_sec1: &[u8],
        revoked: bool,
    ) -> Result<(), SnapshotError> {
        crypto::p256_ecdsa::validate_public_key(p256_sec1)
            .map_err(|_| SnapshotError::InvalidPublicKey)?;
        let per_uid = self.devices.entry(uid).or_default();
        if per_uid.contains_key(&device_id) {
            return Err(SnapshotError::Duplicate);
        }
        per_uid.insert(
            device_id,
            DeviceEntry {
                sec1: p256_sec1.to_vec(),
                revoked,
            },
        );
        Ok(())
    }

    /// Finish building.
    pub fn build(self) -> DeviceSnapshot {
        DeviceSnapshot {
            devices: self.devices,
        }
    }
}

/// The root verifier state machine.
pub struct Verifier<C: Clock = BoottimeClock> {
    signer: crypto::ed25519::Signer,
    verifier_key_id: [u8; 32],
    /// Registered device public keys (with per-device revocation state).
    devices: DeviceMap,
    pending: HashMap<[u8; 16], Pending>,
    /// Concurrent pending count per uid (kept in sync with `pending` for the §15.3 cap).
    per_uid: HashMap<u32, usize>,
    clock: C,
}

impl<C: Clock> Verifier<C> {
    /// Create a verifier from a 32B Ed25519 seed and a clock. Pending requests start empty (a process
    /// restart therefore drops all pending requests, as required by design §16).
    ///
    /// The seed is copied into a zeroizing [`crypto::ed25519::Signer`]; no long-lived raw seed is
    /// retained. Note that `[u8; 32]` is `Copy`, so the caller's own copy and the temporary here are
    /// not auto-zeroized — a key-loading API taking `Zeroizing<[u8; 32]>` (best-effort zeroizing the
    /// temporary) is a follow-up for the registry/key-load task.
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
    /// existing (uid, device_id) registration — active *or* revoked — is not silently overwritten
    /// (design §14.2). Registers as non-revoked.
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
        entry.insert(
            iphone_device_id,
            DeviceEntry {
                sec1: p256_sec1.to_vec(),
                revoked: false,
            },
        );
        Ok(())
    }

    /// Revoke a registered device (a one-way tombstone). A revoked device remains known — so it still
    /// counts as registered for [`register_device`] — but fails verification with
    /// [`VerifyError::RevokedDevice`]. Revoking an already-revoked device is [`RevokeError::AlreadyRevoked`].
    ///
    /// This mutates only the in-memory copy (used by a future running-daemon reload path); the persistent
    /// tombstone is written by [`registry::Registry::revoke`]. The daemon's startup path installs revoked
    /// state via [`Verifier::replace_devices`], not this method.
    pub fn revoke_device(
        &mut self,
        uid: u32,
        iphone_device_id: [u8; 16],
    ) -> Result<(), RevokeError> {
        let entry = self
            .devices
            .get_mut(&uid)
            .and_then(|m| m.get_mut(&iphone_device_id))
            .ok_or(RevokeError::NotRegistered)?;
        if entry.revoked {
            return Err(RevokeError::AlreadyRevoked);
        }
        entry.revoked = true;
        Ok(())
    }

    /// Atomically replace the entire device registry with a validated point-in-time snapshot (design
    /// §14.2 / task 0009 D4-a). This is the daemon's reload path: the whole map is swapped in one
    /// operation so a partially-applied or stale registry is never observable, and pending requests are
    /// untouched (they are keyed independently). Every entry's public key is re-validated here as a
    /// defense in depth even though [`DeviceSnapshot`] can only be built through its validating builder;
    /// on any invalid key nothing is swapped (fail closed).
    pub fn replace_devices(&mut self, snapshot: DeviceSnapshot) -> Result<(), SnapshotError> {
        for per_uid in snapshot.devices.values() {
            for entry in per_uid.values() {
                crypto::p256_ecdsa::validate_public_key(&entry.sec1)
                    .map_err(|_| SnapshotError::InvalidPublicKey)?;
            }
        }
        self.devices = snapshot.devices;
        Ok(())
    }

    /// Number of pending requests (for tests/metrics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Cancel a pending request by id (used by the IPC session on any abnormal termination after a
    /// challenge was issued but before a response is verified). Idempotent: cancelling an unknown or
    /// already-consumed request is a no-op that returns `false`, so a cleanup guard may call it on every
    /// exit path without risking a double-consume.
    pub fn cancel_pending(&mut self, request_id: &[u8; 16]) -> bool {
        self.consume(request_id).is_some()
    }

    /// Drop **all** pending requests (fail closed). Called by the IPC layer when it recovers a poisoned
    /// verifier lock: a panic while the lock was held means some state transition was interrupted, so the
    /// safe response is to invalidate every in-flight challenge rather than reason about partial state.
    /// Registered devices and the signing key are unaffected.
    pub fn fail_closed_reset(&mut self) {
        self.pending.clear();
        self.per_uid.clear();
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
        let device = self
            .devices
            .get(&pending.uid)
            .and_then(|m| m.get(&resp.iphone_device_id))
            .ok_or(VerifyError::UnregisteredDevice)?;
        // A revoked device is known but must never authenticate (design §9.7 step 11, §18.3). The request
        // is already consumed above, so a revoked device also spends its request_id.
        if device.revoked {
            return Err(VerifyError::RevokedDevice);
        }
        // Recompute the hash; the response value must match (malformed otherwise) but is never a sig input.
        if resp.signed_payload_hash != crypto::sha256(&pending.canonical) {
            return Err(VerifyError::HashMismatch);
        }
        // Verify the P-256 signature over the stored canonical bytes.
        crypto::p256_ecdsa::verify(&device.sec1, &pending.canonical, &resp.signature)
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
    fn total_queue_cap_is_enforced_across_uids() {
        // Fill the total cap with MAX_PENDING_PER_UID requests each across enough uids.
        let (mut v, _ph) = setup(MockClock::new(1_000_000_000));
        let uids = MAX_PENDING_TOTAL / MAX_PENDING_PER_UID;
        for uid in 0..uids as u32 {
            for _ in 0..MAX_PENDING_PER_UID {
                let mut c = ctx();
                c.uid = uid;
                v.issue_challenge(&c).unwrap();
            }
        }
        assert_eq!(v.pending_count(), MAX_PENDING_TOTAL);
        // The total cap is checked before the per-uid cap, so a fresh uid is also rejected.
        let mut c = ctx();
        c.uid = 9999;
        assert!(matches!(v.issue_challenge(&c), Err(IssueError::QueueFull)));
    }

    #[test]
    fn per_uid_counter_recovers_after_a_consumed_failure() {
        // Fill the per-uid cap, then let one request be consumed by a failing verify; the uid can issue again.
        let (mut v, _a) = setup(MockClock::new(1_000_000_000));
        let mut first = None;
        for i in 0..MAX_PENDING_PER_UID {
            let issued = v.issue_challenge(&ctx()).unwrap();
            if i == 0 {
                first = Some(issued);
            }
        }
        assert!(matches!(
            v.issue_challenge(&ctx()),
            Err(IssueError::TooManyPendingForUid)
        ));
        // Consume one via a wrong-key (valid DER) response -> SignatureInvalid but consumed.
        let device_b = iphone(&[0x77; 32]);
        let response = device_b.process(&first.unwrap().envelope).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::SignatureInvalid)
        );
        // The per-uid counter recovered, so the uid can issue again.
        assert!(v.issue_challenge(&ctx()).is_ok());
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

    #[test]
    fn revoked_device_fails_verify_and_consumes() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        v.revoke_device(UID, IPHONE_DEV).unwrap();
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::RevokedDevice)
        );
        // The request_id is consumed even on a revoked-device denial.
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn revoke_is_one_way_and_blocks_reregister() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        // Revoking an unknown device is NotRegistered.
        assert_eq!(
            v.revoke_device(UID, [0xAB; 16]),
            Err(RevokeError::NotRegistered)
        );
        v.revoke_device(UID, IPHONE_DEV).unwrap();
        // A second revoke is AlreadyRevoked.
        assert_eq!(
            v.revoke_device(UID, IPHONE_DEV),
            Err(RevokeError::AlreadyRevoked)
        );
        // A revoked registration is still "registered": no silent re-trust (design §14.2).
        assert_eq!(
            v.register_device(UID, IPHONE_DEV, &ph.device_public_key_sec1()),
            Err(RegisterError::AlreadyRegistered)
        );
    }

    #[test]
    fn snapshot_builder_rejects_duplicate_and_invalid_key() {
        let ph = iphone(&DEVICE_SEED);
        let mut b = DeviceSnapshot::builder();
        b.add(UID, IPHONE_DEV, &ph.device_public_key_sec1(), false)
            .unwrap();
        // Same (uid, device_id) twice is a Duplicate.
        assert_eq!(
            b.add(UID, IPHONE_DEV, &ph.device_public_key_sec1(), false),
            Err(SnapshotError::Duplicate)
        );
        // Invalid SEC1 bytes are rejected.
        assert_eq!(
            b.add(UID, [0x01; 16], &[0u8; 5], false),
            Err(SnapshotError::InvalidPublicKey)
        );
    }

    #[test]
    fn replace_devices_installs_snapshot_atomically() {
        // A fresh verifier with no devices; install a snapshot with one active device -> verify succeeds.
        let mut v = Verifier::new(VERIFIER_SEED, MockClock::new(1_000_000_000));
        let ph = iphone(&DEVICE_SEED);
        let mut b = DeviceSnapshot::builder();
        b.add(UID, IPHONE_DEV, &ph.device_public_key_sec1(), false)
            .unwrap();
        v.replace_devices(b.build()).unwrap();
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        assert!(v.verify_response(&response).is_ok());
    }

    #[test]
    fn pending_response_crossing_a_revoke_boundary_is_denied() {
        // task 0009 D7: a challenge is issued while the device is active, then the registry is swapped to
        // a revoked snapshot before the response is verified. The in-flight response must be denied
        // (RevokedDevice) and consumed — the active snapshot's state must not linger.
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        // Swap in a snapshot where the same device is revoked.
        let mut b = DeviceSnapshot::builder();
        b.add(UID, IPHONE_DEV, &ph.device_public_key_sec1(), true)
            .unwrap();
        v.replace_devices(b.build()).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::RevokedDevice)
        );
        assert_eq!(v.pending_count(), 0);
    }
}
