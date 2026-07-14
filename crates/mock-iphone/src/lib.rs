//! mock-iphone — a **partial software mock (crypto skeleton)** of the iPhone (Secure Enclave / Face ID).
//!
//! A test double for exercising the **signing round-trip skeleton** (challenge generation ->
//! verifier signing -> response signing -> verification) **without a real iPhone, on this machine
//! alone**. It implements **only part** of design §9.5.
//!
//! **Implemented (part of design §9.5):**
//! - Ed25519 verifier-signature verification of the envelope (over the raw canonical_challenge bytes).
//! - Layer-A/layer-B validation of the inner challenge (`Challenge::decode`).
//! - `verifier_key_id` matching (design §8.2: equals SHA-256 of the registered Ed25519 public key).
//! - `linux_device_id` matching.
//! - **Number matching** ([`Approval`], task 0011 / P5): the confirmation code is matched against an
//!   **externally supplied** user-entered code (never taken from the challenge, never displayed / echoed),
//!   with injectable Face ID outcome and an injectable approval deadline. See [`Approval`] for the
//!   verify → match → Face ID → sign state machine.
//! - P-256 signing of canonical_challenge.
//!
//! **Not implemented (do not mistake this; deferred to later phases/tasks):**
//! - iPhone-side **expiry (issued/expires) and request_id replay** checks (§9.5 lists them before the
//!   approval screen). The authority for TTL/replay is the verifier (CLOCK_BOOTTIME + atomic consume,
//!   done in P4); the iPhone-side duplicate is a defense-in-depth deferred to a follow-up task. So an
//!   [`Approval`] that reaches its later states means **only** "envelope crypto verified + code matched +
//!   Face ID passed", NOT "all of §9.5 verified".
//! - **Purpose allowlist** (§9.5 required gate before approval): established at pairing (§8.2), tracked as
//!   a P2 completion criterion — see the marked gate point in [`Approval`].
//! - Pairing/registration and a real Secure Enclave.
//!
//! In short, this crate does **not** model the iPhone's full identity assurance. Add the above gates when
//! replacing it with the real device (Swift).

use bifrauth_proto::{Challenge, Envelope, Response, SchemaError};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

/// Failures of mock-iphone processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Failed to decode the envelope (structure/schema).
    EnvelopeInvalid(SchemaError),
    /// The verifier's Ed25519 signature is invalid over canonical_challenge.
    VerifierSignatureInvalid,
    /// The inner challenge failed layer-A/layer-B validation.
    ChallengeInvalid(SchemaError),
    /// The challenge's verifier_key_id does not match SHA-256 of the registered verifier key (design §8.2).
    UnknownVerifierKeyId,
    /// The challenge's linux_device_id does not match the registered verifier.
    UnknownLinuxDevice,
    /// Failed to build the response (unexpected; e.g. DER length).
    ResponseBuild(SchemaError),
    /// The device key seed is invalid.
    BadDeviceKey,
}

/// A software-mock iPhone.
pub struct MockIphone {
    device_id: [u8; 16],
    signing_key: SigningKey,
    // The registered Linux verifier.
    verifier_ed25519_pk: [u8; 32],
    linux_device_id: [u8; 16],
}

impl MockIphone {
    /// Build a mock device. `device_key_seed` is a software P-256 secret key (no Secure Enclave).
    pub fn new(
        device_id: [u8; 16],
        device_key_seed: &[u8; 32],
        verifier_ed25519_pk: [u8; 32],
        linux_device_id: [u8; 16],
    ) -> Result<Self, Error> {
        let signing_key =
            SigningKey::from_slice(device_key_seed).map_err(|_| Error::BadDeviceKey)?;
        Ok(MockIphone {
            device_id,
            signing_key,
            verifier_ed25519_pk,
            linux_device_id,
        })
    }

    /// The device public key for registration (SEC1). The verifier uses it to verify the response signature.
    pub fn device_public_key_sec1(&self) -> Box<[u8]> {
        self.signing_key.verifying_key().to_sec1_bytes()
    }

    /// Verify the envelope's crypto (steps 1-4 of design §9.5) and return the raw canonical challenge
    /// bytes plus the decoded challenge. Does **not** cover expiry / replay / allowlist (see the module
    /// docs); this is only the envelope-crypto gate shared by [`sign_skipping_number_matching`] and
    /// [`MockIphone::begin_approval`].
    fn verify_envelope(&self, envelope_bytes: &[u8]) -> Result<(Vec<u8>, Challenge), Error> {
        let env = Envelope::decode(envelope_bytes).map_err(Error::EnvelopeInvalid)?;
        // Verify the verifier's Ed25519 signature over the raw bytes.
        bifrauth_crypto::ed25519::verify(
            &self.verifier_ed25519_pk,
            &env.canonical_challenge,
            &env.verifier_signature,
        )
        .map_err(|_| Error::VerifierSignatureInvalid)?;
        // Run layer-A/layer-B checks on the same raw bytes.
        let challenge =
            Challenge::decode(&env.canonical_challenge).map_err(Error::ChallengeInvalid)?;
        // verifier_key_id equals SHA-256 of the registered verifier key (design §8.2).
        if challenge.verifier_key_id != bifrauth_crypto::sha256(&self.verifier_ed25519_pk) {
            return Err(Error::UnknownVerifierKeyId);
        }
        // It is a registered Linux host.
        if challenge.linux_device_id != self.linux_device_id {
            return Err(Error::UnknownLinuxDevice);
        }
        Ok((env.canonical_challenge, challenge))
    }

    /// **Legacy crypto skeleton that skips number matching** (verify envelope -> sign, as if the correct
    /// code was entered and Face ID succeeded). It exists **only** to drive the Linux-side state-machine
    /// tests (session / serve / framing) that predate P5 and do not exercise number matching. It is **not**
    /// the faithful device path — the confirmation code is neither required nor matched here — so P5's
    /// number-matching tests and the `NumberMatchingTransport` must **not** use it. Use
    /// [`MockIphone::begin_approval`] for a faithful flow.
    pub fn sign_skipping_number_matching(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let (canonical, challenge) = self.verify_envelope(envelope_bytes)?;
        sign_response(&self.signing_key, self.device_id, &canonical, &challenge)
    }

    /// Begin a faithful number-matching approval (design §9.5, §13.2/§13.3; task 0011 / P5).
    ///
    /// Runs the envelope-crypto gate, then returns an [`EnvelopeChecked`] state that requires the caller
    /// to supply an **externally entered** confirmation code (from the Linux display channel — never taken
    /// from the challenge) and a Face ID outcome before it will sign. `clock`/`deadline_ns` model the
    /// iPhone-local approval window (§16 Face ID wait): `clock.now_ns()` is checked against `deadline_ns`
    /// at each transition and again immediately before signing (TOCTOU-safe).
    ///
    /// Note the returned state means only "envelope crypto verified" — not expiry/replay/allowlist (module
    /// docs). The confirmation code is held internally and is never displayed, echoed, or exposed.
    pub fn begin_approval<C: ApprovalClock>(
        &self,
        envelope_bytes: &[u8],
        clock: C,
        deadline_ns: u64,
    ) -> Result<EnvelopeChecked<C>, ApprovalError> {
        let (canonical, challenge) = self
            .verify_envelope(envelope_bytes)
            .map_err(ApprovalError::Envelope)?;
        // The challenge's confirmation code must be exactly 6 ASCII digits (the schema enforces this at
        // decode; re-check defensively). Held internally, never surfaced.
        if !is_six_ascii_digits(challenge.confirmation_code.as_bytes()) {
            return Err(ApprovalError::MalformedConfirmationCode);
        }
        Ok(EnvelopeChecked {
            inner: ApprovalInner {
                device_id: self.device_id,
                signing_key: self.signing_key.clone(),
                canonical,
                challenge,
                clock,
                deadline_ns,
            },
        })
    }
}

/// A monotonic clock for the iPhone-local approval window (nanoseconds, arbitrary base). Injectable so
/// tests can drive the deadline precisely.
pub trait ApprovalClock {
    fn now_ns(&self) -> u64;
}

/// A test/driver clock whose time is set explicitly. `mock-iphone` is test-support, so this is public.
#[derive(Debug, Clone)]
pub struct ManualClock {
    now_ns: std::rc::Rc<std::cell::Cell<u64>>,
}

impl ManualClock {
    /// Create a clock reading `start_ns`.
    pub fn new(start_ns: u64) -> Self {
        ManualClock {
            now_ns: std::rc::Rc::new(std::cell::Cell::new(start_ns)),
        }
    }
    /// Advance the clock by `delta_ns`.
    pub fn advance(&self, delta_ns: u64) {
        self.now_ns.set(self.now_ns.get() + delta_ns);
    }
}

impl ApprovalClock for ManualClock {
    fn now_ns(&self) -> u64 {
        self.now_ns.get()
    }
}

/// The injected Face ID outcome (design §13.1; P5 failure/cancel injection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceId {
    /// Face ID succeeded (biometry matched).
    Success,
    /// Face ID was denied (biometry did not match).
    Denied,
    /// The user cancelled the Face ID / approval prompt.
    Cancelled,
}

/// Why an [`Approval`] transition failed. **Never carries the expected or entered confirmation code**
/// (nor does its `Debug`), so the code cannot leak through an error value or log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// The envelope failed the crypto gate (signature / decode / verifier_key_id / linux_device_id).
    Envelope(Error),
    /// The challenge's confirmation code is not 6 ASCII digits (malformed; schema should have rejected it).
    MalformedConfirmationCode,
    /// The externally entered code is not 6 ASCII digits.
    EnteredCodeNotSixDigits,
    /// The entered code did not match the challenge's confirmation code.
    CodeMismatch,
    /// Face ID did not succeed (denied or cancelled).
    FaceIdFailed(FaceId),
    /// The iPhone-local approval window elapsed before this step (checked again just before signing).
    Expired,
    /// Building the response failed (unexpected; e.g. DER length).
    ResponseBuild(SchemaError),
}

/// Fields carried through the approval state machine. The confirmation code lives here and is never
/// exposed; this struct deliberately does **not** derive `Debug`.
struct ApprovalInner<C: ApprovalClock> {
    device_id: [u8; 16],
    signing_key: SigningKey,
    canonical: Vec<u8>,
    challenge: Challenge,
    clock: C,
    deadline_ns: u64,
}

impl<C: ApprovalClock> ApprovalInner<C> {
    /// The single deadline gate, called at every transition and just before signing (TOCTOU-safe).
    fn ensure_within_deadline(&self) -> Result<(), ApprovalError> {
        if self.clock.now_ns() >= self.deadline_ns {
            return Err(ApprovalError::Expired);
        }
        Ok(())
    }
}

/// A namespace marker for the approval state machine (see [`MockIphone::begin_approval`]). The states are
/// [`EnvelopeChecked`] -> [`CodeMatched`] -> [`FaceApproved`]; each transition **consumes** `self`, so a
/// terminal (signed or rejected) approval cannot be reused or re-signed.
pub enum Approval {}

/// State: the envelope's crypto is verified. Awaits the externally entered confirmation code.
pub struct EnvelopeChecked<C: ApprovalClock> {
    inner: ApprovalInner<C>,
}

/// State: the entered code matched. Awaits the Face ID outcome.
pub struct CodeMatched<C: ApprovalClock> {
    inner: ApprovalInner<C>,
}

/// State: Face ID succeeded. Awaits the final sign (which re-checks the deadline).
pub struct FaceApproved<C: ApprovalClock> {
    inner: ApprovalInner<C>,
}

impl<C: ApprovalClock> EnvelopeChecked<C> {
    /// Match an **externally entered** confirmation code against the challenge's code (constant-time; the
    /// code is never read from the caller's challenge copy and never surfaced). Consumes `self`.
    ///
    /// NOTE (design §9.5 order): the purpose **allowlist** gate belongs *here*, before code entry, but is
    /// established at pairing (§8.2) and is tracked as a P2 completion criterion — not implemented in this
    /// mock yet (see module docs / docs/progress.md).
    pub fn enter_code(self, entered: &str) -> Result<CodeMatched<C>, ApprovalError> {
        self.inner.ensure_within_deadline()?;
        let entered = entered.as_bytes();
        if !is_six_ascii_digits(entered) {
            return Err(ApprovalError::EnteredCodeNotSixDigits);
        }
        // Constant-time compare over the fixed 6 bytes; do not branch on which digit differs.
        if !ct_eq_six(entered, self.inner.challenge.confirmation_code.as_bytes()) {
            return Err(ApprovalError::CodeMismatch);
        }
        Ok(CodeMatched { inner: self.inner })
    }
}

impl<C: ApprovalClock> CodeMatched<C> {
    /// Apply the (injected) Face ID outcome. Only [`FaceId::Success`] proceeds; denied/cancelled reject.
    /// Consumes `self`.
    pub fn face_id(self, outcome: FaceId) -> Result<FaceApproved<C>, ApprovalError> {
        self.inner.ensure_within_deadline()?;
        match outcome {
            FaceId::Success => Ok(FaceApproved { inner: self.inner }),
            FaceId::Denied | FaceId::Cancelled => Err(ApprovalError::FaceIdFailed(outcome)),
        }
    }
}

impl<C: ApprovalClock> FaceApproved<C> {
    /// Sign the canonical challenge and return the response.v1 bytes. Re-checks the deadline immediately
    /// before signing (TOCTOU-safe), so an approval that expired after Face ID never produces a signature.
    /// Consumes `self`.
    pub fn sign(self) -> Result<Vec<u8>, ApprovalError> {
        self.inner.ensure_within_deadline()?;
        let inner = self.inner;
        sign_response(
            &inner.signing_key,
            inner.device_id,
            &inner.canonical,
            &inner.challenge,
        )
        .map_err(|e| match e {
            Error::ResponseBuild(s) => ApprovalError::ResponseBuild(s),
            other => ApprovalError::Envelope(other),
        })
    }
}

/// Sign the canonical challenge (P-256) and build response.v1 bytes. Reached only after the
/// number-matching + Face ID + deadline gates (see [`Approval`]) or via the legacy skeleton.
fn sign_response(
    signing_key: &SigningKey,
    device_id: [u8; 16],
    canonical: &[u8],
    challenge: &Challenge,
) -> Result<Vec<u8>, Error> {
    let sig: Signature = signing_key.sign(canonical);
    let der = sig.to_der().as_bytes().to_vec();
    let resp = Response {
        protocol_version: challenge.protocol_version,
        request_id: challenge.request_id,
        iphone_device_id: device_id,
        signed_payload_hash: bifrauth_crypto::sha256(canonical),
        signature: der,
    };
    resp.encode().map_err(Error::ResponseBuild)
}

/// Whether `bytes` is exactly 6 ASCII digits.
fn is_six_ascii_digits(bytes: &[u8]) -> bool {
    bytes.len() == 6 && bytes.iter().all(u8::is_ascii_digit)
}

/// Constant-time equality of two 6-byte confirmation codes. Returns false for any non-6 length without
/// leaking which position differs.
fn ct_eq_six(a: &[u8], b: &[u8]) -> bool {
    if a.len() != 6 || b.len() != 6 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..6 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrauth_crypto::{ed25519, p256_ecdsa, sha256};
    use p256::ecdsa::VerifyingKey;

    const LINUX_DEV: [u8; 16] = [0x44; 16];
    const IPHONE_DEV: [u8; 16] = [0x66; 16];

    fn sample_challenge() -> Challenge {
        Challenge {
            protocol_version: 1,
            request_id: [0x11; 16],
            nonce: [0x22; 16],
            verifier_key_id: [0x33; 32],
            linux_device_id: LINUX_DEV,
            linux_device_name: "workstation".into(),
            target_uid: 1000,
            target_username: "alice".into(),
            pam_service: "polkit-1".into(),
            pam_tty: None,
            pam_rhost: Some("host.example".into()),
            requested_action: "polkit-1.authenticate".into(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_015,
            confirmation_code: "012345".into(),
        }
    }

    /// A challenge whose verifier_key_id (SHA-256) matches the given verifier public key.
    fn challenge_for(vpk: &[u8; 32]) -> Challenge {
        let mut c = sample_challenge();
        c.verifier_key_id = sha256(vpk);
        c
    }

    /// The verifier builds an envelope (make an Ed25519 key from the seed, sign canonical, and wrap it).
    fn build_envelope(verifier_seed: &[u8; 32], canonical: &[u8]) -> Vec<u8> {
        let sk = ed25519::signing_key(verifier_seed);
        let sig = ed25519::sign(&sk, canonical);
        Envelope {
            canonical_challenge: canonical.to_vec(),
            verifier_signature: sig,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn end_to_end_challenge_to_verified_response() {
        // The verifier key and the mock-iphone device key.
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();

        // Verifier: build a challenge, make it canonical, and wrap it in an envelope.
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);

        // mock-iphone: process it and return a response.
        let resp_bytes = iphone.sign_skipping_number_matching(&envelope).unwrap();

        // Verifier side: verify the response (P-256 signature over canonical with the mock's registered public key).
        let resp = Response::decode(&resp_bytes).unwrap();
        assert_eq!(resp.request_id, [0x11; 16]);
        assert_eq!(resp.iphone_device_id, IPHONE_DEV);
        // signed_payload_hash equals the value the verifier recomputes from the pending canonical (not trusted).
        assert_eq!(resp.signed_payload_hash, sha256(&canonical));
        // Verify the response signature over the canonical bytes (with the registered iPhone public key).
        let iphone_pk = iphone.device_public_key_sec1();
        assert!(p256_ecdsa::verify(&iphone_pk, &canonical, &resp.signature).is_ok());
    }

    #[test]
    fn rejects_tampered_canonical_with_stale_signature() {
        // Strictly prove the raw-bytes signature boundary:
        // verifier-sign canonical -> tamper exactly one byte of canonical -> rebuild the envelope with
        // the stale signature -> always VerifierSignatureInvalid.
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();

        let canonical = challenge_for(&vpk).encode().unwrap();
        let sig = ed25519::sign(&ed25519::signing_key(&[0x03; 32]), &canonical);

        let mut tampered = canonical.clone();
        tampered[10] ^= 0x01; // tamper one byte of canonical_challenge
        // Signature verification (step 2) runs before Challenge::decode (step 3), so regardless of
        // whether the tampered canonical is valid CBOR, it is rejected first by the stale-signature mismatch.
        let envelope = Envelope {
            canonical_challenge: tampered,
            verifier_signature: sig,
        }
        .encode()
        .unwrap();

        assert_eq!(
            iphone.sign_skipping_number_matching(&envelope),
            Err(Error::VerifierSignatureInvalid)
        );
    }

    #[test]
    fn rejects_wrong_verifier_key_id() {
        // The signature is valid but verifier_key_id does not match SHA-256 of the registered key -> UnknownVerifierKeyId.
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        // sample_challenge's verifier_key_id is [0x33; 32], which does not match sha256(vpk).
        let canonical = sample_challenge().encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);
        assert_eq!(
            iphone.sign_skipping_number_matching(&envelope),
            Err(Error::UnknownVerifierKeyId)
        );
    }

    #[test]
    fn signed_payload_hash_is_not_trusted() {
        // Tampering the response's signed_payload_hash leaves the P-256 signature valid over canonical.
        // The verifier detects the mismatch by comparing against the hash it recomputes from the pending canonical (not trusted).
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);
        let resp_bytes = iphone.sign_skipping_number_matching(&envelope).unwrap();

        let mut resp = Response::decode(&resp_bytes).unwrap();
        resp.signed_payload_hash[0] ^= 0x01; // tamper the hash
        let tampered = resp.encode().unwrap();
        let resp2 = Response::decode(&tampered).unwrap();

        let iphone_pk = iphone.device_public_key_sec1();
        // The signature is still valid over canonical (the signed object is the canonical bytes, not the hash).
        assert!(p256_ecdsa::verify(&iphone_pk, &canonical, &resp2.signature).is_ok());
        // But it does not match the hash the verifier recomputes -> it must not be trusted as an auth input.
        assert_ne!(resp2.signed_payload_hash, sha256(&canonical));
    }

    #[test]
    fn rejects_wrong_verifier_key() {
        // An envelope signed with a different verifier key (attacker seed) is rejected.
        let real_pk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], real_pk, LINUX_DEV).unwrap();
        let canonical = sample_challenge().encode().unwrap();
        let envelope = build_envelope(&[0x07; 32], &canonical);
        assert_eq!(
            iphone.sign_skipping_number_matching(&envelope),
            Err(Error::VerifierSignatureInvalid)
        );
    }

    #[test]
    fn rejects_unknown_linux_device() {
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        // The mock registers a different linux_device_id (verifier_key_id is made to match so we reach 4b).
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, [0x99; 16]).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap(); // linux_device_id = 0x44*16
        let envelope = build_envelope(&[0x03; 32], &canonical);
        assert_eq!(
            iphone.sign_skipping_number_matching(&envelope),
            Err(Error::UnknownLinuxDevice)
        );
    }

    #[test]
    fn shared_crypto_vectors_conformance() {
        // Read spec/vectors/crypto_vectors.tsv and verify the SHA-256/Ed25519/P-256 contracts.
        const TSV: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/crypto_vectors.tsv"
        ));
        let mut m = std::collections::HashMap::new();
        for line in TSV.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('\t').unwrap();
            m.insert(k, from_hex(v));
        }
        let canonical = &m["canonical"];
        let pk: [u8; 32] = m["ed25519_pubkey"].as_slice().try_into().unwrap();
        let sig: [u8; 64] = m["ed25519_sig"].as_slice().try_into().unwrap();

        // Contract 1 (exact regeneration): build the key from the seed; pubkey/sig match the fixture byte-for-byte.
        let seed: [u8; 32] = m["ed25519_seed"].as_slice().try_into().unwrap();
        let sk = ed25519::signing_key(&seed);
        assert_eq!(ed25519::public_key(&sk).to_vec(), m["ed25519_pubkey"]);
        assert_eq!(ed25519::sign(&sk, canonical).to_vec(), m["ed25519_sig"]);
        // Contract 1: SHA-256 is exact too.
        assert_eq!(sha256(canonical).to_vec(), m["sha256"]);
        // Contract 1: Ed25519 verify succeeds.
        assert!(ed25519::verify(&pk, canonical, &sig).is_ok());
        // Contract 2 (verify success): the P-256 DER signature over canonical verifies with the SEC1 public key.
        assert!(p256_ecdsa::verify(&m["p256_sec1"], canonical, &m["p256_der_sig"]).is_ok());

        // negative: against the fixture's canonical_tampered, both signatures fail verification (Swift shares the same hex).
        let tampered = &m["canonical_tampered"];
        assert!(ed25519::verify(&pk, tampered, &sig).is_err());
        assert!(p256_ecdsa::verify(&m["p256_sec1"], tampered, &m["p256_der_sig"]).is_err());

        // Cross-consistency: the crypto canonical is byte-identical to challenge_v1 in messages_golden.
        const GOLDEN: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/messages_golden.tsv"
        ));
        let golden_challenge = GOLDEN
            .lines()
            .find_map(|l| l.strip_prefix("challenge_v1\t"))
            .map(from_hex)
            .expect("challenge_v1 in messages_golden");
        assert_eq!(
            canonical, &golden_challenge,
            "crypto canonical == golden challenge_v1"
        );
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn device_public_key_is_valid_sec1() {
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], [0u8; 32], LINUX_DEV).unwrap();
        let pk = iphone.device_public_key_sec1();
        assert!(VerifyingKey::from_sec1_bytes(&pk).is_ok());
    }

    // ---- number matching (Approval) state machine (task 0011 / P5; design §9.5, §13.2/§13.3, §16) ----

    const VERIFIER_SEED: [u8; 32] = [0x03; 32];
    const DEVICE_SEED: [u8; 32] = [0x55; 32];
    /// The confirmation code embedded in `sample_challenge()` / `challenge_for()`.
    const CODE: &str = "012345";
    const DEADLINE_NS: u64 = 1_000;

    fn matching_setup() -> (MockIphone, Vec<u8>, Vec<u8>) {
        let vpk = ed25519::public_key(&ed25519::signing_key(&VERIFIER_SEED));
        let iphone = MockIphone::new(IPHONE_DEV, &DEVICE_SEED, vpk, LINUX_DEV).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&VERIFIER_SEED, &canonical);
        (iphone, envelope, canonical)
    }

    #[test]
    fn number_matching_happy_path_signs_and_verifies() {
        let (iphone, envelope, canonical) = matching_setup();
        // The user reads the displayed code (== challenge code) and types it. The clock stays before the
        // deadline throughout.
        let resp_bytes = iphone
            .begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS)
            .unwrap()
            .enter_code(CODE)
            .unwrap()
            .face_id(FaceId::Success)
            .unwrap()
            .sign()
            .unwrap();
        let resp = Response::decode(&resp_bytes).unwrap();
        assert_eq!(resp.iphone_device_id, IPHONE_DEV);
        let iphone_pk = iphone.device_public_key_sec1();
        assert!(p256_ecdsa::verify(&iphone_pk, &canonical, &resp.signature).is_ok());
    }

    #[test]
    fn wrong_code_is_rejected_and_never_signs() {
        let (iphone, envelope, _) = matching_setup();
        let matched = iphone
            .begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS)
            .unwrap()
            .enter_code("999999");
        assert_eq!(matched.err(), Some(ApprovalError::CodeMismatch));
    }

    #[test]
    fn entered_code_must_be_exactly_six_ascii_digits() {
        let (iphone, envelope, _) = matching_setup();
        for bad in ["12345", "1234567", "01234a", "", " 01234"] {
            let r = iphone
                .begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS)
                .unwrap()
                .enter_code(bad);
            assert_eq!(
                r.err(),
                Some(ApprovalError::EnteredCodeNotSixDigits),
                "entered {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn face_id_denied_or_cancelled_does_not_sign() {
        for outcome in [FaceId::Denied, FaceId::Cancelled] {
            let (iphone, envelope, _) = matching_setup();
            let r = iphone
                .begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS)
                .unwrap()
                .enter_code(CODE)
                .unwrap()
                .face_id(outcome);
            assert_eq!(r.err(), Some(ApprovalError::FaceIdFailed(outcome)));
        }
    }

    #[test]
    fn approval_expired_before_code_entry_is_rejected() {
        let (iphone, envelope, _) = matching_setup();
        // Clock is already at the deadline: the first transition fails closed.
        let r = iphone
            .begin_approval(&envelope, ManualClock::new(DEADLINE_NS), DEADLINE_NS)
            .unwrap()
            .enter_code(CODE);
        assert_eq!(r.err(), Some(ApprovalError::Expired));
    }

    #[test]
    fn approval_expiring_after_face_id_is_rejected_at_the_sign_gate() {
        // TOCTOU: the code matched and Face ID passed while valid, but the window elapses before signing.
        let (iphone, envelope, _) = matching_setup();
        let clock = ManualClock::new(0);
        let approved = iphone
            .begin_approval(&envelope, clock.clone(), DEADLINE_NS)
            .unwrap()
            .enter_code(CODE)
            .unwrap()
            .face_id(FaceId::Success)
            .unwrap();
        clock.advance(DEADLINE_NS); // now == deadline -> expired
        assert_eq!(approved.sign().err(), Some(ApprovalError::Expired));
    }

    #[test]
    fn envelope_crypto_failure_rejects_before_any_code_handling() {
        // An envelope signed with the wrong verifier key never reaches code entry.
        let vpk = ed25519::public_key(&ed25519::signing_key(&VERIFIER_SEED));
        let iphone = MockIphone::new(IPHONE_DEV, &DEVICE_SEED, vpk, LINUX_DEV).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&[0x07; 32], &canonical); // attacker verifier seed
        let r = iphone.begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS);
        assert!(matches!(
            r.err(),
            Some(ApprovalError::Envelope(Error::VerifierSignatureInvalid))
        ));
    }

    #[test]
    fn confirmation_code_never_appears_in_the_error() {
        // The mismatch error must not leak the expected or entered code (Debug included).
        let (iphone, envelope, _) = matching_setup();
        // `.err().unwrap()` (not `.unwrap_err()`), since the Ok state deliberately has no Debug impl.
        let err = iphone
            .begin_approval(&envelope, ManualClock::new(0), DEADLINE_NS)
            .unwrap()
            .enter_code("999999")
            .err()
            .unwrap();
        let shown = format!("{err:?}");
        assert!(
            !shown.contains(CODE),
            "error must not leak the expected code"
        );
        assert!(
            !shown.contains("999999"),
            "error must not leak the entered code"
        );
    }

    #[test]
    fn constant_time_compare_matches_only_the_exact_code() {
        assert!(ct_eq_six(b"012345", b"012345"));
        assert!(!ct_eq_six(b"012345", b"012346"));
        assert!(!ct_eq_six(b"012345", b"112345"));
        assert!(!ct_eq_six(b"01234", b"012345")); // wrong length -> false, no panic
    }
}
