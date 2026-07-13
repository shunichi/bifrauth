//! mock-iphone — iPhone（Secure Enclave / Face ID）の**ソフトウェア模擬**。
//!
//! Linux 側の「challenge 生成 → verifier 署名 → 応答署名 → 検証」を、**実 iPhone なしで
//! このマシンだけ**で通すためのテスト用ダブル（設計 §9.5、実装計画の mock-iphone フェーズ）。
//!
//! **実機との違い（重要）:**
//! - 秘密鍵は**ソフトウェアの P-256 鍵**で、Secure Enclave は使わない。
//! - **Face ID は常に成功**とみなす。number matching（6桁確認コードの入力照合）・確認コードの
//!   非表示不変条件・pairing/allowlist は**未実装**（後続フェーズ/別タスク）。
//! - よってこれは署名往復の骨格を検証するための **mock** であり、iPhone の本人性保証は模さない。

use bifrauth_proto::{Challenge, Envelope, Response, SchemaError};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

/// mock-iphone の処理失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// envelope の decode に失敗（構造/スキーマ）。
    EnvelopeInvalid(SchemaError),
    /// verifier の Ed25519 署名が canonical_challenge に対して不正。
    VerifierSignatureInvalid,
    /// 内包 challenge の層A/層B 検査に失敗。
    ChallengeInvalid(SchemaError),
    /// challenge の linux_device_id が登録済み verifier と一致しない。
    UnknownLinuxDevice,
    /// 応答の構築に失敗（想定外。DER 長など）。
    ResponseBuild(SchemaError),
    /// デバイス鍵シードが不正。
    BadDeviceKey,
}

/// ソフトウェア模擬の iPhone。
pub struct MockIphone {
    device_id: [u8; 16],
    signing_key: SigningKey,
    // 登録済み Linux verifier。
    verifier_ed25519_pk: [u8; 32],
    linux_device_id: [u8; 16],
}

impl MockIphone {
    /// 模擬デバイスを作る。`device_key_seed` はソフト P-256 秘密鍵（Secure Enclave 非使用）。
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

    /// 登録用のデバイス公開鍵（SEC1）。verifier はこれで応答署名を検証する。
    pub fn device_public_key_sec1(&self) -> Box<[u8]> {
        self.signing_key.verifying_key().to_sec1_bytes()
    }

    /// envelope を処理して response.v1 のバイト列を返す（設計 §9.5）。
    ///
    /// 手順: (1) envelope decode → (2) verifier 署名を **canonical_challenge の生バイト列**へ
    /// Ed25519 検証 → (3) 同じ生バイト列を [`Challenge::decode`] で層A/層B 検査 →
    /// (4) linux_device_id を照合 → (5)（Face ID mock 成功）canonical_challenge を P-256 署名 →
    /// (6) response.v1 を構築。
    pub fn process(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let env = Envelope::decode(envelope_bytes).map_err(Error::EnvelopeInvalid)?;

        // (2) 生バイト列に対して verifier の Ed25519 署名を検証。
        bifrauth_crypto::ed25519::verify(
            &self.verifier_ed25519_pk,
            &env.canonical_challenge,
            &env.verifier_signature,
        )
        .map_err(|_| Error::VerifierSignatureInvalid)?;

        // (3) 同じ生バイト列を層A/層B 検査。
        let challenge =
            Challenge::decode(&env.canonical_challenge).map_err(Error::ChallengeInvalid)?;

        // (4) 登録済み Linux 端末か。
        if challenge.linux_device_id != self.linux_device_id {
            return Err(Error::UnknownLinuxDevice);
        }

        // (5) Face ID mock 成功 → canonical_challenge を P-256 署名（message API, SHA-256 内部1回）。
        let sig: Signature = self.signing_key.sign(&env.canonical_challenge);
        let der = sig.to_der().as_bytes().to_vec();

        // (6) response.v1 を構築。signed_payload_hash = SHA-256(canonical_challenge)。
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

    /// verifier が envelope を作る（seed から Ed25519 鍵を作り canonical を署名して包む）。
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
        // verifier 鍵、mock-iphone のデバイス鍵。
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();

        // verifier: challenge を作り canonical にして envelope 化。
        let canonical = sample_challenge().encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);

        // mock-iphone: 処理して response を返す。
        let resp_bytes = iphone.process(&envelope).unwrap();

        // verifier 側: response を検証（P-256 署名を canonical に対し、mock の登録公開鍵で）。
        let resp = Response::decode(&resp_bytes).unwrap();
        assert_eq!(resp.request_id, [0x11; 16]);
        assert_eq!(resp.iphone_device_id, IPHONE_DEV);
        // signed_payload_hash は verifier が保留 canonical から再計算した値と一致（信用はしない）。
        assert_eq!(resp.signed_payload_hash, sha256(&canonical));
        // 応答署名を canonical bytes に対して検証（登録済み iPhone 公開鍵で）。
        let iphone_pk = iphone.device_public_key_sec1();
        assert!(p256_ecdsa::verify(&iphone_pk, &canonical, &resp.signature).is_ok());
    }

    #[test]
    fn rejects_tampered_envelope() {
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        let canonical = sample_challenge().encode().unwrap();
        let mut envelope = build_envelope(&[0x03; 32], &canonical);
        // canonical_challenge の 1 バイトを改ざん（envelope 内、bstr 本体の位置）。
        let n = envelope.len();
        envelope[n / 2] ^= 0x01;
        // envelope の decode に通っても署名不一致で拒否される（または decode 失敗）。
        assert!(iphone.process(&envelope).is_err());
    }

    #[test]
    fn rejects_wrong_verifier_key() {
        // 別の verifier 鍵（attacker seed）で署名した envelope は拒否。
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
        // mock は別の linux_device_id を登録している。
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, [0x99; 16]).unwrap();
        let canonical = sample_challenge().encode().unwrap(); // linux_device_id = 0x44*16
        let envelope = build_envelope(&[0x03; 32], &canonical);
        assert_eq!(iphone.process(&envelope), Err(Error::UnknownLinuxDevice));
    }

    #[test]
    fn device_public_key_is_valid_sec1() {
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], [0u8; 32], LINUX_DEV).unwrap();
        let pk = iphone.device_public_key_sec1();
        assert!(VerifyingKey::from_sec1_bytes(&pk).is_ok());
    }
}
