//! bifrauth-crypto — BifrAuth cryptographic primitives (P0).
//!
//! Operates on `bifrauth-proto` canonical bytes. Follows design §9 and profile §5.1/§6.
//! - [`sha256`]: `signed_payload_hash = SHA-256(canonical_challenge)`。
//! - [`ed25519`]: verifier challenge signing (the envelope's 64B signature).
//! - [`p256_ecdsa`]: verify the iPhone response signature (X9.62 DER) with strict DER + r,s in [1,n-1], SHA-256.
//! - [`csprng`]: generation of request_id/nonce and confirmation_code.

/// Reasons a cryptographic operation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The public-key bytes are invalid.
    BadPublicKey,
    /// The signature bytes/DER are invalid (format, length, or r,s range).
    BadSignature,
    /// Signature verification failed (mismatch, including small-order/malleability).
    VerifyFailed,
    /// Failed to obtain OS randomness. Callers must treat this as an auth failure (e.g. password
    /// fallback) and **must not panic the process**.
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
    //! Ed25519 (the verifier's challenge signing).
    use super::Error;
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

    /// Build a signing key from a 32B secret-key seed.
    pub fn signing_key(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    /// The 32B public key for a signing key (distributed by the verifier at pairing time).
    pub fn public_key(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    /// Sign `msg` and return the 64B signature.
    pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
        sk.sign(msg).to_bytes()
    }

    /// **Strictly** verify a 64B signature over `msg` with a 32B public key.
    ///
    /// `verify_strict` also rejects small-order/group-element malleability of R and the public key
    /// (choose strict verification at the authentication boundary).
    pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(pk).map_err(|_| Error::BadPublicKey)?;
        let signature = Signature::from_bytes(sig);
        vk.verify_strict(msg, &signature)
            .map_err(|_| Error::VerifyFailed)
    }
}

pub mod p256_ecdsa {
    //! P-256 ECDSA signature verification (iPhone response, profile §5.1).
    //!
    //! Signatures are X9.62 DER (<=72B). `from_der` guarantees strict DER parsing and r,s in [1,n-1].
    //! Verification uses the message API (SHA-256 once internally); `msg` is the whole canonical bytes.
    //! The initial version does not require low-S (profile §5.1).
    use super::Error;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    /// Verify a DER signature over `msg` with a SEC1-format public key.
    pub fn verify(pk_sec1: &[u8], msg: &[u8], der_sig: &[u8]) -> Result<(), Error> {
        let vk = VerifyingKey::from_sec1_bytes(pk_sec1).map_err(|_| Error::BadPublicKey)?;
        let sig = Signature::from_der(der_sig).map_err(|_| Error::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| Error::VerifyFailed)
    }
}

pub mod csprng {
    //! CSPRNG (design §16). Uses OS cryptographic randomness (`getrandom`).
    //!
    //! On a randomness-source failure, return [`Error::RandomFailed`] **without panicking**. Callers
    //! (verifier/PAM) treat it as an auth failure and fall back to password (avoid DoS).
    use super::Error;

    /// Upper bound to remove modulo bias (the 4,294,000,000 accepted values are a multiple of 1,000,000).
    const CC_LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);

    /// N bytes of cryptographic randomness.
    pub fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
        let mut b = [0u8; N];
        getrandom::fill(&mut b).map_err(|_| Error::RandomFailed)?;
        Ok(b)
    }

    /// A uniform 6-digit confirmation code (`[0-9]{6}`, 000000..=999999). `RandomFailed` on RNG failure.
    pub fn confirmation_code() -> Result<String, Error> {
        confirmation_code_with(|b| getrandom::fill(b).map_err(|_| Error::RandomFailed))
    }

    /// Testable core. Inject `fill` to deterministically exercise the rejection branch and RNG failure.
    /// Uses rejection sampling to generate 000000..=999999 uniformly.
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
            // Reject v >= CC_LIMIT and retry (bias removal).
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_biased_region_then_accepts() {
            // Deterministic fill: return the reject region (CC_LIMIT) first, then a value giving 123456.
            let mut calls = 0u32;
            let code = confirmation_code_with(|b| {
                calls += 1;
                let v: u32 = if calls == 1 { CC_LIMIT } else { 123_456 };
                *b = v.to_le_bytes();
                Ok(())
            })
            .unwrap();
            assert_eq!(code, "123456");
            assert_eq!(calls, 2, "skip the reject region once, then accept");
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
        // SHA-256 of "abc".
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
        // A tampered msg fails.
        assert!(ed25519::verify(&pk, b"tampered", &sig).is_err());
        // A different key fails.
        let other = ed25519::public_key(&ed25519::signing_key(&[9u8; 32]));
        assert!(ed25519::verify(&other, msg, &sig).is_err());
    }

    #[test]
    fn ed25519_small_order_pubkeys_rejected() {
        // Known small-order point encodings (rejected by strict verification; no panic).
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
            ], // small-order point corresponding to p-1
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

        // A valid signature verifies successfully.
        assert!(p256_ecdsa::verify(&sec1, msg, der.as_bytes()).is_ok());
        // A tampered msg fails.
        assert!(p256_ecdsa::verify(&sec1, b"other msg", der.as_bytes()).is_err());
        // Malformed DER is BadSignature.
        assert_eq!(
            p256_ecdsa::verify(&sec1, msg, &[0x00, 0x01, 0x02]),
            Err(Error::BadSignature)
        );
        // A different key fails.
        let sk2 = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let sec1_2 = sk2.verifying_key().to_sec1_bytes();
        assert!(p256_ecdsa::verify(&sec1_2, msg, der.as_bytes()).is_err());
        // An invalid public key is BadPublicKey.
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
        // Assume a valid signature passes (the regression baseline).
        assert!(p256_ecdsa::verify(&sec1, msg, &valid).is_ok());

        // (a) trailing bytes
        let mut trailing = valid.clone();
        trailing.push(0xAA);
        // (b) truncated
        let truncated = &valid[..valid.len() - 1];
        // (c) INTEGER instead of SEQUENCE
        let not_seq: &[u8] = &[0x02, 0x01, 0x01];
        // (d) r=0: SEQUENCE{ INT 0, INT 1 }
        let r_zero: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        // (e) s=0
        let s_zero: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
        // (f) non-minimal long-form length (6B body expressed as 0x81 0x06)
        let nonminimal_len: &[u8] = &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        // (g) INTEGER with an unnecessary leading 00 (r = 00 01)
        let leading_zero: &[u8] = &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        // (h) negative INTEGER (leading 0x80, no leading 00)
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
        // Fix the upper-bound guarantee r,s in [1, n-1] (the n boundary).
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes();
        let msg = b"m";
        // The P-256 group order n.
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        // INTEGER n: 33B with a leading 0x00 because the high bit is set (0x02 0x21 0x00 || N).
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
        // r=n, s=1 and r=1, s=n are both out of range -> BadSignature.
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
        // Shape only (uniformity is proven by the deterministic boundary tests in csprng::tests).
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
        assert_ne!(a, b); // collisions are effectively impossible
    }
}
