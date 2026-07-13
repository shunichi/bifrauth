//! bifrauth-crypto — BifrAuth の暗号プリミティブ（P0）。
//!
//! 対象は `bifrauth-proto` の canonical バイト列。設計 §9、プロファイル §5.1/§6 に従う。
//! - [`sha256`]: `signed_payload_hash = SHA-256(canonical_challenge)`。
//! - [`ed25519`]: verifier challenge 署名（envelope の 64B 署名）。
//! - [`p256_ecdsa`]: iPhone 応答署名（X9.62 DER）の検証（strict DER + r,s∈[1,n-1]、SHA-256）。
//! - [`csprng`]: request_id/nonce と confirmation_code の生成。

/// 暗号操作の失敗理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// 公開鍵のバイト列が不正。
    BadPublicKey,
    /// 署名のバイト列/DER が不正（形式・長さ・r,s 範囲）。
    BadSignature,
    /// 署名検証に失敗（不一致）。
    VerifyFailed,
}

/// `SHA-256(data)`。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub mod ed25519 {
    //! Ed25519（verifier の challenge 署名）。
    use super::Error;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// 32B の秘密鍵シードから署名鍵を作る。
    pub fn signing_key(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    /// 署名鍵に対応する 32B 公開鍵（verifier がペアリング時に配布する）。
    pub fn public_key(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    /// `msg` に署名し、64B の署名を返す。
    pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
        sk.sign(msg).to_bytes()
    }

    /// 32B 公開鍵で `msg` に対する 64B 署名を検証する。
    pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(pk).map_err(|_| Error::BadPublicKey)?;
        let signature = Signature::from_bytes(sig);
        vk.verify(msg, &signature).map_err(|_| Error::VerifyFailed)
    }
}

pub mod p256_ecdsa {
    //! P-256 ECDSA 署名検証（iPhone 応答、プロファイル §5.1）。
    //!
    //! 署名は X9.62 DER（≤72B）。`from_der` が strict DER パースと r,s∈[1,n-1] を保証する。
    //! 検証は message API（SHA-256 を内部で 1 回）で、`msg` は canonical bytes 全体。
    //! 初版は low-S を要求しない（プロファイル §5.1）。
    use super::Error;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    /// SEC1 形式の公開鍵で、`msg` に対する DER 署名を検証する。
    pub fn verify(pk_sec1: &[u8], msg: &[u8], der_sig: &[u8]) -> Result<(), Error> {
        let vk = VerifyingKey::from_sec1_bytes(pk_sec1).map_err(|_| Error::BadPublicKey)?;
        let sig = Signature::from_der(der_sig).map_err(|_| Error::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| Error::VerifyFailed)
    }
}

pub mod csprng {
    //! CSPRNG（設計 §16）。OS の暗号乱数（`getrandom`）を使う。

    /// N バイトの暗号乱数。
    pub fn random_bytes<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        getrandom::fill(&mut b).expect("OS CSPRNG");
        b
    }

    /// 一様な 6 桁の確認コード（`[0-9]{6}`, 000000..=999999）。
    pub fn confirmation_code() -> String {
        // 剰余バイアスを避けるため rejection sampling。
        const LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);
        loop {
            let v = u32::from_le_bytes(random_bytes::<4>());
            if v < LIMIT {
                return format!("{:06}", v % 1_000_000);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha256_known_vector() {
        // "abc" の SHA-256。
        let h = sha256(b"abc");
        assert_eq!(
            hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let seed = [7u8; 32];
        let sk = ed25519::signing_key(&seed);
        let pk = ed25519::public_key(&sk);
        let msg = b"bifrauth canonical challenge";
        let sig = ed25519::sign(&sk, msg);
        assert!(ed25519::verify(&pk, msg, &sig).is_ok());
        // 改ざんした msg は失敗。
        assert!(ed25519::verify(&pk, b"tampered", &sig).is_err());
        // 別鍵は失敗。
        let other = ed25519::public_key(&ed25519::signing_key(&[9u8; 32]));
        assert!(ed25519::verify(&other, msg, &sig).is_err());
    }

    #[test]
    fn p256_verify_roundtrip_and_rejections() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes();
        let msg = b"canonical challenge bytes";
        let sig: Signature = sk.sign(msg);
        let der = sig.to_der();

        // 正当署名は検証成功。
        assert!(p256_ecdsa::verify(&sec1, msg, der.as_bytes()).is_ok());
        // 改ざん msg は失敗。
        assert!(p256_ecdsa::verify(&sec1, b"other msg", der.as_bytes()).is_err());
        // 不正 DER は BadSignature。
        assert_eq!(
            p256_ecdsa::verify(&sec1, msg, &[0x00, 0x01, 0x02]),
            Err(Error::BadSignature)
        );
        // 別鍵は失敗。
        let sk2 = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let sec1_2 = sk2.verifying_key().to_sec1_bytes();
        assert!(p256_ecdsa::verify(&sec1_2, msg, der.as_bytes()).is_err());
        // 不正な公開鍵は BadPublicKey。
        assert_eq!(
            p256_ecdsa::verify(&[0u8; 10], msg, der.as_bytes()),
            Err(Error::BadPublicKey)
        );
    }

    #[test]
    fn csprng_confirmation_code_shape() {
        for _ in 0..100 {
            let c = csprng::confirmation_code();
            assert_eq!(c.len(), 6);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn csprng_random_bytes_differ() {
        let a: [u8; 16] = csprng::random_bytes();
        let b: [u8; 16] = csprng::random_bytes();
        assert_ne!(a, b); // 衝突は事実上起きない
    }
}
