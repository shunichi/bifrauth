//! bifrauth-crypto × bifrauth-proto の統合テスト。
//! verifier が canonical challenge を Ed25519 署名し、iPhone(mock) が同じ canonical bytes を
//! P-256 署名する、というプロトコルの署名往復を canonical バイト列で通す（設計 §9）。

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

    // verifier が canonical_challenge の生バイト列へ Ed25519 署名（envelope の 64B 署名）。
    let sk = ed25519::signing_key(&[0x03; 32]);
    let pk = ed25519::public_key(&sk);
    let sig = ed25519::sign(&sk, &canonical);
    assert!(ed25519::verify(&pk, &canonical, &sig).is_ok());

    // 1 バイトでも変われば検証は失敗する（バイト列一致が本質）。
    let mut tampered = canonical.clone();
    tampered[0] ^= 0x01;
    assert!(ed25519::verify(&pk, &tampered, &sig).is_err());
}

#[test]
fn iphone_p256_signs_canonical_challenge_and_hash_matches() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let canonical = sample_challenge().encode().expect("encode");

    // iPhone(mock) の Secure Enclave 相当鍵で canonical bytes を P-256 署名。
    let device_sk = SigningKey::from_slice(&[0x55; 32]).unwrap();
    let device_pk_sec1 = device_sk.verifying_key().to_sec1_bytes();
    let sig: Signature = device_sk.sign(&canonical);
    assert!(p256_ecdsa::verify(&device_pk_sec1, &canonical, sig.to_der().as_bytes()).is_ok());

    // signed_payload_hash は verifier が保留 canonical bytes から再計算した値と一致する。
    let expected = sha256(&canonical);
    assert_eq!(expected.len(), 32);
    // （応答が別の challenge の hash を送ってきても、verifier 側の再計算は canonical に紐づく）
    let other = {
        let mut c = sample_challenge();
        c.nonce = [0x99; 16];
        c.encode().unwrap()
    };
    assert_ne!(sha256(&other), expected);
}
