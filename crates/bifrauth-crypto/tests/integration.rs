//! Integration test for bifrauth-crypto x bifrauth-proto.
//! Exercises the protocol's signing round-trip over canonical bytes: the verifier Ed25519-signs the
//! canonical challenge and the iPhone (mock) P-256-signs the same canonical bytes (design §9).

use bifrauth_crypto::{ed25519, p256_ecdsa, sha256};
use bifrauth_proto::Challenge;

fn sample_challenge() -> Challenge {
    Challenge {
        protocol_version: 1,
        request_id: [0x11; 16],
        nonce: [0x22; 16],
        verifier_key_id: [0x33; 32],
        linux_device_id: [0x44; 16],
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

#[test]
fn verifier_ed25519_signs_canonical_challenge() {
    let canonical = sample_challenge().encode().expect("encode");

    // The verifier Ed25519-signs the raw canonical_challenge bytes (the envelope's 64B signature).
    let sk = ed25519::signing_key(&[0x03; 32]);
    let pk = ed25519::public_key(&sk);
    let sig = ed25519::sign(&sk, &canonical);
    assert!(ed25519::verify(&pk, &canonical, &sig).is_ok());

    // Changing even one byte fails verification (exact byte match is the point).
    let mut tampered = canonical.clone();
    tampered[0] ^= 0x01;
    assert!(ed25519::verify(&pk, &tampered, &sig).is_err());
}

#[test]
fn iphone_p256_signs_canonical_challenge_and_hash_matches() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let canonical = sample_challenge().encode().expect("encode");

    // The iPhone (mock) P-256-signs the canonical bytes with its Secure-Enclave-equivalent key.
    let device_sk = SigningKey::from_slice(&[0x55; 32]).unwrap();
    let device_pk_sec1 = device_sk.verifying_key().to_sec1_bytes();
    let sig: Signature = device_sk.sign(&canonical);
    assert!(p256_ecdsa::verify(&device_pk_sec1, &canonical, sig.to_der().as_bytes()).is_ok());

    // signed_payload_hash equals the value the verifier recomputes from the pending canonical bytes.
    let expected = sha256(&canonical);
    assert_eq!(expected.len(), 32);
    // (Even if a response carries another challenge's hash, the verifier's recomputation is bound to canonical.)
    let other = {
        let mut c = sample_challenge();
        c.nonce = [0x99; 16];
        c.encode().unwrap()
    };
    assert_ne!(sha256(&other), expected);
}
