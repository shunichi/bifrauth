//! mock-iphone — iPhone（Secure Enclave / Face ID）の**部分的ソフトウェア模擬（crypto skeleton）**。
//!
//! Linux 側の「challenge 生成 → verifier 署名 → 応答署名 → 検証」の**署名往復の骨格**を、
//! **実 iPhone なしでこのマシンだけ**で通すためのテスト用ダブル。設計 §9.5 の**一部のみ**を実装する。
//!
//! **実装済み（設計 §9.5 のうち）:**
//! - envelope の Ed25519 verifier 署名検証（canonical_challenge の生バイト列に対して）。
//! - 内包 challenge の層A/層B 検査（`Challenge::decode`）。
//! - `verifier_key_id` の照合（設計 §8.2: 登録 Ed25519 公開鍵の SHA-256 と一致するか）。
//! - `linux_device_id` の照合。
//! - canonical_challenge への P-256 署名（Face ID は**常に成功**とみなす mock）。
//!
//! **未実装（誤認しないこと。後続フェーズ/別タスクへ deferred）:**
//! - 期限（issued/expires・CLOCK_BOOTTIME）検査、request_id の replay 防止。
//! - 用途 allowlist、number matching（6桁確認コードの入力照合）と確認コード非表示不変条件。
//! - Face ID の失敗/キャンセル注入（P5 状態機械）。pairing/登録、Secure Enclave 実体。
//!
//! すなわち本 crate は **iPhone の本人性保証を模さない**。実機（Swift）置換時に上記 gate を足す。

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
    /// challenge の verifier_key_id が登録 verifier 鍵の SHA-256 と一致しない（設計 §8.2）。
    UnknownVerifierKeyId,
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

        // (4a) verifier_key_id が登録 verifier 鍵の SHA-256 と一致するか（設計 §8.2）。
        if challenge.verifier_key_id != bifrauth_crypto::sha256(&self.verifier_ed25519_pk) {
            return Err(Error::UnknownVerifierKeyId);
        }
        // (4b) 登録済み Linux 端末か。
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

    /// verifier 公開鍵に対応する正しい verifier_key_id（SHA-256）を設定した challenge。
    fn challenge_for(vpk: &[u8; 32]) -> Challenge {
        let mut c = sample_challenge();
        c.verifier_key_id = sha256(vpk);
        c
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
        let canonical = challenge_for(&vpk).encode().unwrap();
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
    fn rejects_tampered_canonical_with_stale_signature() {
        // raw バイト列への署名境界を厳密に証明する:
        // canonical を verifier 署名 → canonical の1バイトだけ改ざん → 古い署名のまま
        // envelope を再構築 → 必ず VerifierSignatureInvalid（decode は通る）。
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();

        let canonical = challenge_for(&vpk).encode().unwrap();
        let sig = ed25519::sign(&ed25519::signing_key(&[0x03; 32]), &canonical);

        let mut tampered = canonical.clone();
        tampered[10] ^= 0x01; // canonical_challenge を1バイト改ざん
        // 署名検証(step 2)は Challenge::decode(step 3) より前なので、改ざん canonical が
        // CBOR として妥当か否かに関わらず、古い署名との不一致で先に弾かれる。
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
        // 署名は正当だが verifier_key_id が登録鍵の SHA-256 と不一致 → UnknownVerifierKeyId。
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        // sample_challenge の verifier_key_id は [0x33; 32] で sha256(vpk) と一致しない。
        let canonical = sample_challenge().encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);
        assert_eq!(iphone.process(&envelope), Err(Error::UnknownVerifierKeyId));
    }

    #[test]
    fn signed_payload_hash_is_not_trusted() {
        // 応答の signed_payload_hash を改ざんしても P-256 署名は canonical に対して有効なまま。
        // verifier は保留 canonical から再計算した hash と比較して不一致を検出する（信用しない）。
        let vpk = ed25519::public_key(&ed25519::signing_key(&[0x03; 32]));
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, LINUX_DEV).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap();
        let envelope = build_envelope(&[0x03; 32], &canonical);
        let resp_bytes = iphone.process(&envelope).unwrap();

        let mut resp = Response::decode(&resp_bytes).unwrap();
        resp.signed_payload_hash[0] ^= 0x01; // hash を改ざん
        let tampered = resp.encode().unwrap();
        let resp2 = Response::decode(&tampered).unwrap();

        let iphone_pk = iphone.device_public_key_sec1();
        // 署名は依然 canonical に対して有効（署名対象は hash ではなく canonical bytes）。
        assert!(p256_ecdsa::verify(&iphone_pk, &canonical, &resp2.signature).is_ok());
        // だが verifier が再計算する hash とは一致しない → 認証入力として信用してはならない。
        assert_ne!(resp2.signed_payload_hash, sha256(&canonical));
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
        // mock は別の linux_device_id を登録している（verifier_key_id は一致させ 4b に到達させる）。
        let iphone = MockIphone::new(IPHONE_DEV, &[0x55; 32], vpk, [0x99; 16]).unwrap();
        let canonical = challenge_for(&vpk).encode().unwrap(); // linux_device_id = 0x44*16
        let envelope = build_envelope(&[0x03; 32], &canonical);
        assert_eq!(iphone.process(&envelope), Err(Error::UnknownLinuxDevice));
    }

    #[test]
    fn shared_crypto_vectors_conformance() {
        // spec/vectors/crypto_vectors.tsv を読み、SHA-256/Ed25519/P-256 の契約を検証する。
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

        // 契約1(exact 再生成): seed から鍵を作り、pubkey/sig が fixture と byte 一致。
        let seed: [u8; 32] = m["ed25519_seed"].as_slice().try_into().unwrap();
        let sk = ed25519::signing_key(&seed);
        assert_eq!(ed25519::public_key(&sk).to_vec(), m["ed25519_pubkey"]);
        assert_eq!(ed25519::sign(&sk, canonical).to_vec(), m["ed25519_sig"]);
        // 契約1: SHA-256 も exact。
        assert_eq!(sha256(canonical).to_vec(), m["sha256"]);
        // 契約1: Ed25519 verify 成功。
        assert!(ed25519::verify(&pk, canonical, &sig).is_ok());
        // 契約2(検証成功): P-256 は SEC1 公開鍵で canonical への DER 署名が verify 成功。
        assert!(p256_ecdsa::verify(&m["p256_sec1"], canonical, &m["p256_der_sig"]).is_ok());

        // negative: fixture の canonical_tampered に対して両署名とも検証失敗（Swift も同じ hex で共有）。
        let tampered = &m["canonical_tampered"];
        assert!(ed25519::verify(&pk, tampered, &sig).is_err());
        assert!(p256_ecdsa::verify(&m["p256_sec1"], tampered, &m["p256_der_sig"]).is_err());

        // 相互整合: crypto の canonical は messages_golden の challenge_v1 と byte 同一。
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
