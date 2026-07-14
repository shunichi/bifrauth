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
//! - P-256 signing of canonical_challenge (a mock where Face ID **always succeeds**).
//!
//! **Not implemented (do not mistake this; deferred to later phases/tasks):**
//! - Expiry (issued/expires, CLOCK_BOOTTIME) checks and request_id replay prevention.
//! - Purpose allowlist, number matching (entering the 6-digit confirmation code), and the invariant that the code is not displayed.
//! - Face ID failure/cancel injection (P5 state machine). Pairing/registration and a real Secure Enclave.
//!
//! In short, this crate does **not** model the iPhone's identity assurance. Add the above gates when replacing it with the real device (Swift).

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

    /// Process an envelope and return the response.v1 bytes (design §9.5).
    ///
    /// Steps: (1) decode the envelope -> (2) Ed25519-verify the verifier signature over the **raw
    /// canonical_challenge bytes** -> (3) run layer-A/layer-B checks on the same raw bytes via
    /// [`Challenge::decode`] -> (4) match linux_device_id -> (5) (Face ID mock success) P-256-sign
    /// canonical_challenge -> (6) build response.v1.
    pub fn process(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let env = Envelope::decode(envelope_bytes).map_err(Error::EnvelopeInvalid)?;

        // (2) Verify the verifier's Ed25519 signature over the raw bytes.
        bifrauth_crypto::ed25519::verify(
            &self.verifier_ed25519_pk,
            &env.canonical_challenge,
            &env.verifier_signature,
        )
        .map_err(|_| Error::VerifierSignatureInvalid)?;

        // (3) Run layer-A/layer-B checks on the same raw bytes.
        let challenge =
            Challenge::decode(&env.canonical_challenge).map_err(Error::ChallengeInvalid)?;

        // (4a) Whether verifier_key_id equals SHA-256 of the registered verifier key (design §8.2).
        if challenge.verifier_key_id != bifrauth_crypto::sha256(&self.verifier_ed25519_pk) {
            return Err(Error::UnknownVerifierKeyId);
        }
        // (4b) Whether it is a registered Linux host.
        if challenge.linux_device_id != self.linux_device_id {
            return Err(Error::UnknownLinuxDevice);
        }

        // (5) Face ID mock success -> P-256-sign canonical_challenge (message API, SHA-256 once internally).
        let sig: Signature = self.signing_key.sign(&env.canonical_challenge);
        let der = sig.to_der().as_bytes().to_vec();

        // (6) Build response.v1. signed_payload_hash = SHA-256(canonical_challenge).
        let resp = Response {
            protocol_version: challenge.protocol_version,
            request_id: challenge.request_id,
            iphone_device_id: self.device_id,
            signed_payload_hash: bifrauth_crypto::sha256(&env.canonical_challenge),
            signature: der,
        };
        resp.encode().map_err(Error::ResponseBuild)
    }
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
        let resp_bytes = iphone.process(&envelope).unwrap();

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
            iphone.process(&envelope),
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
        assert_eq!(iphone.process(&envelope), Err(Error::UnknownVerifierKeyId));
    }

    #[test]
    fn signed_payload_hash_is_not_trusted() {
        // Tampering the response's signed_payload_hash leaves the P-256 signature valid over canonical.
        // The verifier detects the mismatch by comparing against the hash it recomputes from the pending canonical (not trusted).
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);
        let resp_bytes = iphone.process(&envelope).unwrap();

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
            iphone.process(&envelope),
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
        assert_eq!(iphone.process(&envelope), Err(Error::UnknownLinuxDevice));
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
}
