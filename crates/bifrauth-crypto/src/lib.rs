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
    /// 署名検証に失敗（不一致、small-order/malleability を含む）。
    VerifyFailed,
    /// OS 乱数源の取得に失敗。呼び出し側は認証失敗として扱い（password フォールバック等）、
    /// **プロセスを panic させない**。
    RandomFailed,
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
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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

    /// 32B 公開鍵で `msg` に対する 64B 署名を **strict** 検証する。
    ///
    /// `verify_strict` は R と公開鍵の small-order/group-element malleability も拒否する
    /// （認証の検証境界は strict を選ぶ）。
    pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(pk).map_err(|_| Error::BadPublicKey)?;
        let signature = Signature::from_bytes(sig);
        vk.verify_strict(msg, &signature)
            .map_err(|_| Error::VerifyFailed)
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
    //!
    //! 乱数源障害は **panic させず** [`Error::RandomFailed`] を返す。呼び出し側（verifier/PAM）は
    //! 認証失敗として扱い、password フォールバックへ落とす（DoS を避ける）。
    use super::Error;

    /// 剰余バイアス排除の上限（受理個数 4,294,000,000 は 1,000,000 の倍数）。
    const CC_LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);

    /// N バイトの暗号乱数。
    pub fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
        let mut b = [0u8; N];
        getrandom::fill(&mut b).map_err(|_| Error::RandomFailed)?;
        Ok(b)
    }

    /// 一様な 6 桁の確認コード（`[0-9]{6}`, 000000..=999999）。乱数障害時は `RandomFailed`。
    pub fn confirmation_code() -> Result<String, Error> {
        confirmation_code_with(|b| getrandom::fill(b).map_err(|_| Error::RandomFailed))
    }

    /// テスト可能なコア。`fill` を注入して rejection 分岐と乱数障害を決定論的に検証できる。
    /// rejection sampling で 000000..=999999 を一様に生成する。
    fn confirmation_code_with<F>(mut fill: F) -> Result<String, Error>
    where
        F: FnMut(&mut [u8; 4]) -> Result<(), Error>,
    {
        loop {
            let mut buf = [0u8; 4];
            fill(&mut buf)?;
            let v = u32::from_le_bytes(buf);
            if v < CC_LIMIT {
                return Ok(format!("{:06}", v % 1_000_000));
            }
            // v >= CC_LIMIT は棄却してやり直す（バイアス排除）。
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_biased_region_then_accepts() {
            // 1回目は棄却域（CC_LIMIT）、2回目は 123456 になる値を返す決定論的 fill。
            let mut calls = 0u32;
            let code = confirmation_code_with(|b| {
                calls += 1;
                let v: u32 = if calls == 1 { CC_LIMIT } else { 123_456 };
                *b = v.to_le_bytes();
                Ok(())
            })
            .unwrap();
            assert_eq!(code, "123456");
            assert_eq!(calls, 2, "棄却域を1回スキップしてから採用する");
        }

        #[test]
        fn propagates_random_failure() {
            let r = confirmation_code_with(|_| Err(Error::RandomFailed));
            assert_eq!(r, Err(Error::RandomFailed));
        }

        #[test]
        fn code_is_zero_padded_six_digits() {
            // v=5 → "000005"
            let code = confirmation_code_with(|b| {
                *b = 5u32.to_le_bytes();
                Ok(())
            })
            .unwrap();
            assert_eq!(code, "000005");
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
    fn ed25519_small_order_pubkeys_rejected() {
        // 既知の small-order point エンコード（strict 検証で拒否される。panic しない）。
        let small_order: [[u8; 32]; 3] = [
            [0u8; 32], // order 4
            {
                let mut a = [0u8; 32];
                a[0] = 1; // identity (order 1)
                a
            },
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ], // p-1 相当の small-order 点
        ];
        let sig = [0u8; 64];
        for pk in &small_order {
            assert!(ed25519::verify(pk, b"m", &sig).is_err());
        }
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
    fn p256_negative_der_regression() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes();
        let msg = b"m";
        let sig: Signature = sk.sign(msg);
        let valid: Vec<u8> = sig.to_der().as_bytes().to_vec();
        // 正当署名は通ることを前提にする（回帰の基準）。
        assert!(p256_ecdsa::verify(&sec1, msg, &valid).is_ok());

        // (a) trailing bytes
        let mut trailing = valid.clone();
        trailing.push(0xAA);
        // (b) truncated
        let truncated = &valid[..valid.len() - 1];
        // (c) SEQUENCE ではなく INTEGER
        let not_seq: &[u8] = &[0x02, 0x01, 0x01];
        // (d) r=0: SEQUENCE{ INT 0, INT 1 }
        let r_zero: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        // (e) s=0
        let s_zero: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
        // (f) 非最小の long-form 長（本体6Bを 0x81 0x06 で表す）
        let nonminimal_len: &[u8] = &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        // (g) INTEGER に不要な leading 00（r = 00 01）
        let leading_zero: &[u8] = &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        // (h) 負の INTEGER（先頭 0x80、leading 00 なし）
        let negative_int: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];

        for (name, der) in [
            ("trailing", trailing.as_slice()),
            ("truncated", truncated),
            ("not_seq", not_seq),
            ("r_zero", r_zero),
            ("s_zero", s_zero),
            ("nonminimal_len", nonminimal_len),
            ("leading_zero", leading_zero),
            ("negative_int", negative_int),
        ] {
            assert_eq!(
                p256_ecdsa::verify(&sec1, msg, der),
                Err(Error::BadSignature),
                "case {name} must be BadSignature"
            );
        }
    }

    #[test]
    fn p256_rejects_r_or_s_equal_to_order() {
        use p256::ecdsa::SigningKey;
        // 上限 r,s ∈ [1, n-1] の保証（n 境界）を固定する。
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes();
        let msg = b"m";
        // P-256 の位数 n。
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        // INTEGER n: 高位ビットが立つので leading 0x00 を付けた 33B（0x02 0x21 0x00 || N）。
        let int_n = {
            let mut v = vec![0x02u8, 0x21, 0x00];
            v.extend_from_slice(&N);
            v
        };
        let int_one = [0x02u8, 0x01, 0x01];
        let seq = |a: &[u8], b: &[u8]| {
            let mut body = a.to_vec();
            body.extend_from_slice(b);
            let mut out = vec![0x30u8, body.len() as u8];
            out.extend_from_slice(&body);
            out
        };
        // r=n, s=1 / r=1, s=n はいずれも範囲外 → BadSignature。
        assert_eq!(
            p256_ecdsa::verify(&sec1, msg, &seq(&int_n, &int_one)),
            Err(Error::BadSignature),
            "r=n"
        );
        assert_eq!(
            p256_ecdsa::verify(&sec1, msg, &seq(&int_one, &int_n)),
            Err(Error::BadSignature),
            "s=n"
        );
    }

    #[test]
    fn csprng_confirmation_code_shape() {
        // 形状のみ（一様性の証明は csprng::tests の決定論境界テストで担保）。
        for _ in 0..100 {
            let c = csprng::confirmation_code().unwrap();
            assert_eq!(c.len(), 6);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn csprng_random_bytes_differ() {
        let a: [u8; 16] = csprng::random_bytes().unwrap();
        let b: [u8; 16] = csprng::random_bytes().unwrap();
        assert_ne!(a, b); // 衝突は事実上起きない
    }
}
