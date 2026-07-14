//! Layer B: schema validation and encoding of BifrAuth messages.
//!
//! The normative spec is `spec/cbor-profile.md` §4 (challenge.v1) / §5 (response.v1) / §6 (envelope.v1).
//! For a `Value` deemed canonical by layer A ([`crate::cbor`]), it checks all-keys-required and exact/range.
//! Each schema is a map with contiguous keys 0..N-1, so combined with the "ascending, unique keys"
//! guaranteed by `cbor::scan_structure`, "entry count == N and the i-th key == i" rules out extra/missing/duplicate/order violations at once.
//!
//! Text content is checked by [`TextPolicy`]: byte length, ASCII, control, bidi, plus **rejection of
//! Unicode 16.0 unassigned (Cn, vendored table)** and an **NFC normalization check** (profile §7/§7.1).
//! Rust/Swift acceptance-set agreement is ensured by the vendored Cn table and shared vectors.

use crate::cbor::{self, Limits, Value};
use crate::unicode_cn;
use unicode_normalization::UnicodeNormalization;

/// The initial protocol version (profile §10 mapping table).
pub const PROTOCOL_VERSION: u64 = 1;

pub const MESSAGE_TYPE_CHALLENGE: &str = "bifrauth.challenge.v1";
pub const MESSAGE_TYPE_RESPONSE: &str = "bifrauth.response.v1";
pub const SIGNATURE_ALGORITHM: &str = "ECDSA_P256_SHA256_DER";
pub const VERIFIER_SIGNATURE_ALGORITHM: &str = "Ed25519";

const EPOCH_MAX: u64 = 253_402_300_799; // year 9999, < 2^53
const TTL_MIN: u64 = 1;
const TTL_MAX: u64 = 30;
const UID_MAX: u64 = 4_294_967_294; // reject (uid_t)-1 = 4294967295

const CHALLENGE_MAX_TOTAL: usize = 4096;
const ENVELOPE_MAX_TOTAL: usize = 4608;
const RESPONSE_MAX_TOTAL: usize = 512;

// Field byte limits (profile §4/§5/§6)
const MAX_DEVICE_NAME: usize = 128;
const MAX_USERNAME: usize = 256;
const MAX_PAM_SERVICE: usize = 128;
const MAX_PAM_TTY_RHOST: usize = 256;
const MAX_REQUESTED_ACTION: usize = 256;
const MAX_DEVICE_ID_TEXT: usize = 128; // response.iphone_device_id is a 16B bstr, but leave room for future hint display
const MAX_DER_SIGNATURE: usize = 72; // maximum length of a P-256 X9.62 DER

/// Reasons schema validation can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// A layer-A (canonical) failure.
    Cbor(cbor::Error),
    /// The top-level value is not a map.
    NotMap,
    /// The entry count differs from expected.
    WrongEntryCount { expected: usize, got: usize },
    /// The i-th key differs from expected (= i) (extra/missing/order).
    WrongKey { pos: usize, expected: u64, got: u64 },
    /// A field has the wrong CBOR type.
    WrongType { key: u64 },
    /// A numeric value is out of the allowed range.
    OutOfRange { key: u64 },
    /// A byte/text length is out of spec.
    BadLength { key: u64 },
    /// Text violates the ASCII/control/bidi constraints.
    BadText { key: u64 },
    /// Text is not in NFC normalized form (profile §7).
    NotNfc { key: u64 },
    /// Text contains a code point that is unassigned (Cn) in Unicode 16.0 (profile §7).
    Unassigned { key: u64 },
    /// `message_type` does not match.
    MessageTypeMismatch,
    /// A fixed-string field (e.g. algorithm) does not match.
    FixedStringMismatch { key: u64 },
    /// The TTL (expires - issued) is out of range, or issued >= expires.
    TtlOutOfRange,
}

impl From<cbor::Error> for SchemaError {
    fn from(e: cbor::Error) -> Self {
        SchemaError::Cbor(e)
    }
}

/// Content policy for text fields (profile §7/§7.1).
///
/// Checks: byte-length range, ASCII-only (when specified), rejection of C0 (U+0000..U+001F, incl. NUL) /
/// C1 (U+0080..U+009F) control and Bidi_Control code points, **rejection of Unicode 16.0 unassigned (Cn)**,
/// and a **check that the text is in NFC normalized form**.
///
/// NFC/unassigned must agree between Rust and Swift on the acceptance set (§7.1):
/// - The unassigned check uses the vendored Unicode 16.0 Cn table ([`unicode_cn`]), not a library
///   category table. **Reject 16.0-unassigned first**, then check NFC.
/// - The NFC check compares the NFC transform of the latest-stable `unicode-normalization` scalar-by-scalar
///   (not via `==`). Since we have gated to 16.0-assigned, normalization stability makes the result match 16.0 even on newer Unicode versions.
struct TextPolicy;

// Bidi_Control=Yes (Unicode 16.0): ALM, LRM, RLM, LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
const BIDI_CONTROL: [u32; 12] = [
    0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
];

impl TextPolicy {
    fn forbidden_char(ch: char) -> bool {
        let c = ch as u32;
        // C0 (incl. NUL) and C1 control.
        if c <= 0x1f || (0x80..=0x9f).contains(&c) {
            return true;
        }
        BIDI_CONTROL.contains(&c)
    }

    /// Determine whether the input is already in NFC form. Unassigned (16.0 Cn) must be rejected before
    /// calling this (the normalization-stability precondition).
    ///
    /// Compare the code-point sequence of the NFC transform with the input's, using an iterator.
    /// Rust's `str`/`String` `==` is **byte (code-unit) exact**, so `s == s.nfc().collect::<String>()` would
    /// also be correct, but we use the iterator `eq` to avoid allocating the intermediate String.
    /// Note that on the Swift side `String ==` is **canonical equivalence** and cannot be used; a raw
    /// `unicodeScalars`/`utf8` sequence comparison is required (profile §7.1). Note the reasons differ per language.
    fn is_nfc(s: &str) -> bool {
        s.nfc().eq(s.chars())
    }

    /// Check byte length `min..=max`, optionally ASCII-only, and control/bidi/unassigned/non-NFC.
    fn check(
        s: &str,
        key: u64,
        min: usize,
        max: usize,
        ascii_only: bool,
    ) -> Result<(), SchemaError> {
        let len = s.len();
        if len < min || len > max {
            return Err(SchemaError::BadLength { key });
        }
        for ch in s.chars() {
            if ascii_only && !ch.is_ascii() {
                return Err(SchemaError::BadText { key });
            }
            if Self::forbidden_char(ch) {
                return Err(SchemaError::BadText { key });
            }
            // Reject unassigned (16.0 Cn) before the NFC check (to satisfy the stability precondition).
            if unicode_cn::is_cn(ch as u32) {
                return Err(SchemaError::Unassigned { key });
            }
        }
        if !Self::is_nfc(s) {
            return Err(SchemaError::NotNfc { key });
        }
        Ok(())
    }
}

// ---- Typed extraction from Value ----

fn take_uint(v: &Value, key: u64) -> Result<u64, SchemaError> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(SchemaError::WrongType { key }),
    }
}

fn take_bytes_exact<const N: usize>(v: &Value, key: u64) -> Result<[u8; N], SchemaError> {
    match v {
        Value::Bytes(b) if b.len() == N => {
            Ok(<[u8; N]>::try_from(b.as_slice()).expect("len checked"))
        }
        Value::Bytes(_) => Err(SchemaError::BadLength { key }),
        _ => Err(SchemaError::WrongType { key }),
    }
}

fn take_text(v: &Value, key: u64) -> Result<&str, SchemaError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(SchemaError::WrongType { key }),
    }
}

fn take_text_or_null(v: &Value, key: u64) -> Result<Option<&str>, SchemaError> {
    match v {
        Value::Text(s) => Ok(Some(s)),
        Value::Null => Ok(None),
        _ => Err(SchemaError::WrongType { key }),
    }
}

/// Strictly check the map has contiguous keys 0..N-1 and return the value slice.
fn map_entries(v: &Value, n: usize) -> Result<&[(u64, Value)], SchemaError> {
    let Value::Map(entries) = v else {
        return Err(SchemaError::NotMap);
    };
    if entries.len() != n {
        return Err(SchemaError::WrongEntryCount {
            expected: n,
            got: entries.len(),
        });
    }
    for (i, (k, _)) in entries.iter().enumerate() {
        if *k != i as u64 {
            return Err(SchemaError::WrongKey {
                pos: i,
                expected: i as u64,
                got: *k,
            });
        }
    }
    Ok(entries)
}

fn expect_fixed(v: &Value, key: u64, expected: &str) -> Result<(), SchemaError> {
    let s = take_text(v, key)?;
    if s == expected {
        Ok(())
    } else if key == 0 {
        Err(SchemaError::MessageTypeMismatch)
    } else {
        Err(SchemaError::FixedStringMismatch { key })
    }
}

// ---- challenge.v1 ----

/// `bifrauth.challenge.v1` (profile §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub protocol_version: u64,
    pub request_id: [u8; 16],
    pub nonce: [u8; 16],
    pub verifier_key_id: [u8; 32],
    pub linux_device_id: [u8; 16],
    pub linux_device_name: String,
    pub target_uid: u32,
    pub target_username: String,
    pub pam_service: String,
    pub pam_tty: Option<String>,
    pub pam_rhost: Option<String>,
    pub requested_action: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub confirmation_code: String,
}

fn challenge_limits() -> Limits {
    Limits {
        max_total: CHALLENGE_MAX_TOTAL,
        max_depth: 1,
        max_bytes: 32, // verifier_key_id
        max_text: MAX_USERNAME,
        max_map_entries: 16,
    }
}

impl Challenge {
    /// Check the layer-B constraints on all fields (always called after decode and before encode).
    /// **No implicit normalization** — a violation is an Err.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SchemaError::OutOfRange { key: 1 });
        }
        // Exact byte lengths are guaranteed by the types ([u8; N]).
        TextPolicy::check(&self.linux_device_name, 6, 1, MAX_DEVICE_NAME, false)?;
        if self.target_uid as u64 > UID_MAX {
            return Err(SchemaError::OutOfRange { key: 7 });
        }
        TextPolicy::check(&self.target_username, 8, 1, MAX_USERNAME, false)?;
        TextPolicy::check(&self.pam_service, 9, 1, MAX_PAM_SERVICE, false)?;
        if let Some(s) = &self.pam_tty {
            TextPolicy::check(s, 10, 1, MAX_PAM_TTY_RHOST, false)?;
        }
        if let Some(s) = &self.pam_rhost {
            TextPolicy::check(s, 11, 1, MAX_PAM_TTY_RHOST, false)?;
        }
        TextPolicy::check(&self.requested_action, 12, 1, MAX_REQUESTED_ACTION, false)?;
        if self.issued_at > EPOCH_MAX {
            return Err(SchemaError::OutOfRange { key: 13 });
        }
        if self.expires_at > EPOCH_MAX {
            return Err(SchemaError::OutOfRange { key: 14 });
        }
        if self.expires_at <= self.issued_at {
            return Err(SchemaError::TtlOutOfRange);
        }
        let ttl = self.expires_at - self.issued_at;
        if !(TTL_MIN..=TTL_MAX).contains(&ttl) {
            return Err(SchemaError::TtlOutOfRange);
        }
        // confirmation_code: ASCII [0-9]{6} exact.
        if self.confirmation_code.len() != 6
            || !self.confirmation_code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(SchemaError::BadText { key: 15 });
        }
        Ok(())
    }

    /// Validate and reconstruct from canonical bytes (layer A + typed extraction + layer-B `validate`).
    pub fn decode(bytes: &[u8]) -> Result<Challenge, SchemaError> {
        let v = cbor::scan_structure(bytes, challenge_limits())?;
        let e = map_entries(&v, 16)?;

        // Extract types, exact byte lengths, and fixed strings (structure).
        expect_fixed(&e[0].1, 0, MESSAGE_TYPE_CHALLENGE)?;
        let protocol_version = take_uint(&e[1].1, 1)?;
        let request_id = take_bytes_exact::<16>(&e[2].1, 2)?;
        let nonce = take_bytes_exact::<16>(&e[3].1, 3)?;
        let verifier_key_id = take_bytes_exact::<32>(&e[4].1, 4)?;
        let linux_device_id = take_bytes_exact::<16>(&e[5].1, 5)?;
        let linux_device_name = take_text(&e[6].1, 6)?.to_owned();
        // uid is stored as u32, so reject out-of-range here before constructing (validate rechecks it too).
        let uid = take_uint(&e[7].1, 7)?;
        if uid > UID_MAX {
            return Err(SchemaError::OutOfRange { key: 7 });
        }
        let target_username = take_text(&e[8].1, 8)?.to_owned();
        let pam_service = take_text(&e[9].1, 9)?.to_owned();
        let pam_tty = take_text_or_null(&e[10].1, 10)?.map(str::to_owned);
        let pam_rhost = take_text_or_null(&e[11].1, 11)?.map(str::to_owned);
        let requested_action = take_text(&e[12].1, 12)?.to_owned();
        let issued_at = take_uint(&e[13].1, 13)?;
        let expires_at = take_uint(&e[14].1, 14)?;
        let confirmation_code = take_text(&e[15].1, 15)?.to_owned();

        let c = Challenge {
            protocol_version,
            request_id,
            nonce,
            verifier_key_id,
            linux_device_id,
            linux_device_name,
            target_uid: uid as u32,
            target_username,
            pam_service,
            pam_tty,
            pam_rhost,
            requested_action,
            issued_at,
            expires_at,
            confirmation_code,
        };
        c.validate()?;
        Ok(c)
    }

    /// Validate, then encode to canonical bytes. Invalid content is an Err (no normalization).
    pub fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        let entries = vec![
            (0u64, Value::Text(MESSAGE_TYPE_CHALLENGE.to_owned())),
            (1, Value::Uint(self.protocol_version)),
            (2, Value::Bytes(self.request_id.to_vec())),
            (3, Value::Bytes(self.nonce.to_vec())),
            (4, Value::Bytes(self.verifier_key_id.to_vec())),
            (5, Value::Bytes(self.linux_device_id.to_vec())),
            (6, Value::Text(self.linux_device_name.clone())),
            (7, Value::Uint(self.target_uid as u64)),
            (8, Value::Text(self.target_username.clone())),
            (9, Value::Text(self.pam_service.clone())),
            (10, opt_text(&self.pam_tty)),
            (11, opt_text(&self.pam_rhost)),
            (12, Value::Text(self.requested_action.clone())),
            (13, Value::Uint(self.issued_at)),
            (14, Value::Uint(self.expires_at)),
            (15, Value::Text(self.confirmation_code.clone())),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }
}

fn opt_text(o: &Option<String>) -> Value {
    match o {
        Some(s) => Value::Text(s.clone()),
        None => Value::Null,
    }
}

// ---- envelope.v1 ----

/// `bifrauth.envelope.v1` (profile §6). The inner canonical_challenge is held as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub canonical_challenge: Vec<u8>,
    pub verifier_signature: [u8; 64],
}

fn envelope_limits() -> Limits {
    Limits {
        max_total: ENVELOPE_MAX_TOTAL,
        max_depth: 1,
        max_bytes: CHALLENGE_MAX_TOTAL, // canonical_challenge
        max_text: VERIFIER_SIGNATURE_ALGORITHM.len(),
        max_map_entries: 3,
    }
}

impl Envelope {
    /// Layer-B constraints: canonical_challenge is 1..=CHALLENGE_MAX_TOTAL bytes.
    /// The verifier_signature length is guaranteed by the type ([u8; 64]).
    pub fn validate(&self) -> Result<(), SchemaError> {
        let len = self.canonical_challenge.len();
        if len == 0 || len > CHALLENGE_MAX_TOTAL {
            return Err(SchemaError::BadLength { key: 0 });
        }
        Ok(())
    }

    /// Reconstruct the envelope.
    ///
    /// **Important (profile §6/§8):** the returned [`Envelope::canonical_challenge`] is **unvalidated raw
    /// bytes**. This is kept as-is deliberately, because the design verifies the Ed25519 signature over the
    /// raw bytes. The caller must: (1) verify `verifier_signature` against the **raw bytes** of
    /// `canonical_challenge` with the registered verifier public key -> (2) run layer-A/layer-B checks on the
    /// **same bytes** via [`Challenge::decode`] -> (3) match the pending request state (request_id/nonce/
    /// expiry, etc.). **Do not mistake a merely decoded `Envelope` for a validated Challenge.**
    pub fn decode(bytes: &[u8]) -> Result<Envelope, SchemaError> {
        let v = cbor::scan_structure(bytes, envelope_limits())?;
        let e = map_entries(&v, 3)?;
        let canonical_challenge = match &e[0].1 {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SchemaError::WrongType { key: 0 }),
        };
        expect_fixed(&e[1].1, 1, VERIFIER_SIGNATURE_ALGORITHM)?;
        let verifier_signature = take_bytes_exact::<64>(&e[2].1, 2)?;
        let env = Envelope {
            canonical_challenge,
            verifier_signature,
        };
        env.validate()?;
        Ok(env)
    }

    /// Validate, then encode to canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        let entries = vec![
            (0u64, Value::Bytes(self.canonical_challenge.clone())),
            (1, Value::Text(VERIFIER_SIGNATURE_ALGORITHM.to_owned())),
            (2, Value::Bytes(self.verifier_signature.to_vec())),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }
}

// ---- response.v1 ----

/// `bifrauth.response.v1` (profile §5).
///
/// Note: `signed_payload_hash` is **not trusted as an authentication input**. authd recomputes it from the
/// pending challenge and treats a mismatch as malformed. Signature verification is done against the stored canonical bytes (profile §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub protocol_version: u64,
    pub request_id: [u8; 16],
    pub iphone_device_id: [u8; 16],
    pub signed_payload_hash: [u8; 32],
    pub signature: Vec<u8>, // X9.62 DER, 1..=72B (strict DER checks live in the crypto layer)
}

fn response_limits() -> Limits {
    Limits {
        max_total: RESPONSE_MAX_TOTAL,
        max_depth: 1,
        max_bytes: 72, // signature DER upper bound
        max_text: MAX_DEVICE_ID_TEXT.max(SIGNATURE_ALGORITHM.len()),
        max_map_entries: 7,
    }
}

impl Response {
    /// Layer-B constraints: protocol_version==1; signature is 1..=72B (strict DER lives in the crypto layer).
    /// Exact-byte-length fields are guaranteed by the types.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SchemaError::OutOfRange { key: 1 });
        }
        let len = self.signature.len();
        if len == 0 || len > MAX_DER_SIGNATURE {
            return Err(SchemaError::BadLength { key: 6 });
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Response, SchemaError> {
        let v = cbor::scan_structure(bytes, response_limits())?;
        let e = map_entries(&v, 7)?;
        expect_fixed(&e[0].1, 0, MESSAGE_TYPE_RESPONSE)?;
        let protocol_version = take_uint(&e[1].1, 1)?;
        let request_id = take_bytes_exact::<16>(&e[2].1, 2)?;
        let iphone_device_id = take_bytes_exact::<16>(&e[3].1, 3)?;
        let signed_payload_hash = take_bytes_exact::<32>(&e[4].1, 4)?;
        expect_fixed(&e[5].1, 5, SIGNATURE_ALGORITHM)?;
        let signature = match &e[6].1 {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SchemaError::WrongType { key: 6 }),
        };
        let r = Response {
            protocol_version,
            request_id,
            iphone_device_id,
            signed_payload_hash,
            signature,
        };
        r.validate()?;
        Ok(r)
    }

    /// Validate, then encode to canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        let entries = vec![
            (0u64, Value::Text(MESSAGE_TYPE_RESPONSE.to_owned())),
            (1, Value::Uint(self.protocol_version)),
            (2, Value::Bytes(self.request_id.to_vec())),
            (3, Value::Bytes(self.iphone_device_id.to_vec())),
            (4, Value::Bytes(self.signed_payload_hash.to_vec())),
            (5, Value::Text(SIGNATURE_ALGORITHM.to_owned())),
            (6, Value::Bytes(self.signature.clone())),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_challenge() -> Challenge {
        Challenge {
            protocol_version: 1,
            request_id: [1u8; 16],
            nonce: [2u8; 16],
            verifier_key_id: [3u8; 32],
            linux_device_id: [4u8; 16],
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
    fn challenge_roundtrip() {
        let c = sample_challenge();
        let bytes = c.encode().expect("encode ok");
        assert!(bytes.len() <= CHALLENGE_MAX_TOTAL);
        let back = Challenge::decode(&bytes).expect("decode ok");
        assert_eq!(c, back);
    }

    // encode validates self, so an invalid struct is an Err at encode() time (no normalization).
    #[test]
    fn challenge_encode_rejects_bad_uid() {
        let mut c = sample_challenge();
        c.target_uid = u32::MAX; // 4294967295 = (uid_t)-1
        assert_eq!(c.encode(), Err(SchemaError::OutOfRange { key: 7 }));
    }

    #[test]
    fn challenge_encode_rejects_bad_ttl() {
        let mut c = sample_challenge();
        c.expires_at = c.issued_at + 31; // TTL 31 > 30
        assert_eq!(c.encode(), Err(SchemaError::TtlOutOfRange));
        c.expires_at = c.issued_at; // 0
        assert_eq!(c.encode(), Err(SchemaError::TtlOutOfRange));
    }

    #[test]
    fn challenge_encode_rejects_bad_confirmation_code() {
        let mut c = sample_challenge();
        c.confirmation_code = "12345".into(); // 5 digits
        assert_eq!(c.encode(), Err(SchemaError::BadText { key: 15 }));
        c.confirmation_code = "12a456".into(); // non-digit
        assert_eq!(c.encode(), Err(SchemaError::BadText { key: 15 }));
    }

    #[test]
    fn challenge_encode_rejects_control_and_bidi() {
        let mut c = sample_challenge();
        c.linux_device_name = "work\u{0000}station".into(); // NUL
        assert_eq!(c.encode(), Err(SchemaError::BadText { key: 6 }));
        let mut c2 = sample_challenge();
        c2.target_username = "al\u{202e}ice".into(); // RLO (bidi)
        assert_eq!(c2.encode(), Err(SchemaError::BadText { key: 8 }));
    }

    #[test]
    fn challenge_encode_rejects_bad_protocol_version() {
        let mut c = sample_challenge();
        c.protocol_version = 2;
        assert_eq!(c.encode(), Err(SchemaError::OutOfRange { key: 1 }));
    }

    #[test]
    fn challenge_encode_rejects_non_nfc() {
        // The decomposed form of "é" (e + U+0301 combining acute) is non-NFC.
        let mut c = sample_challenge();
        c.target_username = "e\u{0301}".into();
        assert_eq!(c.encode(), Err(SchemaError::NotNfc { key: 8 }));
    }

    #[test]
    fn challenge_accepts_nfc_composed() {
        // The composed "é" (U+00E9) is NFC and can round-trip.
        let mut c = sample_challenge();
        c.target_username = "caf\u{00E9}".into();
        let back = Challenge::decode(&c.encode().unwrap()).unwrap();
        assert_eq!(back.target_username, "caf\u{00E9}");
    }

    #[test]
    fn challenge_encode_rejects_unassigned() {
        // U+0378 is unassigned (Cn) in Unicode 16.0.
        let mut c = sample_challenge();
        c.linux_device_name = "ws\u{0378}".into();
        assert_eq!(c.encode(), Err(SchemaError::Unassigned { key: 6 }));
    }

    /// Against the cross-language vectors (`spec/vectors/text_policy.tsv`), check that TextPolicy's result
    /// matches the expected category, with Rust as the oracle. Swift reads the same fixture.
    #[test]
    fn text_policy_vectors_conformance() {
        const TSV: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/text_policy.tsv"
        ));
        let mut checked = 0;
        for line in TSV.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            assert!(cols.len() >= 3, "malformed vector line: {line:?}");
            let (id, expected, scalars) = (cols[0], cols[1], cols[2]);
            let s: String = scalars
                .split_whitespace()
                .map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap())
                .collect();
            // Length constraints are separate, so disable them with min=0/large max and look only at the text content policy.
            let got = match TextPolicy::check(&s, 0, 0, 8192, false) {
                Ok(()) => "ok",
                Err(SchemaError::NotNfc { .. }) => "not_nfc",
                Err(SchemaError::Unassigned { .. }) => "unassigned",
                Err(SchemaError::BadText { .. }) => "bad_text",
                Err(SchemaError::BadLength { .. }) => "bad_length",
                Err(e) => panic!("unexpected error for {id}: {e:?}"),
            };
            assert_eq!(got, expected, "vector {id}: got {got}, expected {expected}");
            checked += 1;
        }
        assert!(checked >= 10, "expected many vectors, got {checked}");
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Check that the golden messages (`spec/vectors/messages_golden.tsv`) decode and, when re-encoded,
    /// return the same canonical bytes (both directions / stability).
    #[test]
    fn messages_golden_conformance() {
        const TSV: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/messages_golden.tsv"
        ));
        let mut checked = 0;
        for line in TSV.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, hex) = line.split_once('\t').expect("id<TAB>hex");
            let bytes = from_hex(hex);
            match id {
                "challenge_v1" => {
                    let m = Challenge::decode(&bytes).expect("decode challenge");
                    assert_eq!(m.encode().unwrap(), bytes, "challenge re-encode");
                }
                "envelope_v1" => {
                    let m = Envelope::decode(&bytes).expect("decode envelope");
                    assert_eq!(m.encode().unwrap(), bytes, "envelope re-encode");
                }
                "response_v1" => {
                    let m = Response::decode(&bytes).expect("decode response");
                    assert_eq!(m.encode().unwrap(), bytes, "response re-encode");
                }
                other => panic!("unknown golden id: {other}"),
            }
            checked += 1;
        }
        assert_eq!(checked, 3, "expected 3 golden messages");
    }

    #[test]
    fn challenge_null_tty_rhost_roundtrip() {
        let mut c = sample_challenge();
        c.pam_tty = None;
        c.pam_rhost = None;
        let back = Challenge::decode(&c.encode().unwrap()).unwrap();
        assert_eq!(back.pam_tty, None);
        assert_eq!(back.pam_rhost, None);
    }

    #[test]
    fn challenge_rejects_wrong_message_type() {
        // Directly build a map with a different string for key0.
        let mut entries: Vec<(u64, Value)> = vec![(0, Value::Text("bifrauth.challenge.v2".into()))];
        for k in 1..16u64 {
            entries.push((k, Value::Uint(0)));
        }
        let bytes = cbor::encode(&Value::Map(entries));
        assert_eq!(
            Challenge::decode(&bytes),
            Err(SchemaError::MessageTypeMismatch)
        );
    }

    #[test]
    fn challenge_rejects_missing_key() {
        // 15 entries (one missing).
        let mut entries: Vec<(u64, Value)> = vec![(0, Value::Text(MESSAGE_TYPE_CHALLENGE.into()))];
        for k in 1..15u64 {
            entries.push((k, Value::Uint(0)));
        }
        let bytes = cbor::encode(&Value::Map(entries));
        assert_eq!(
            Challenge::decode(&bytes),
            Err(SchemaError::WrongEntryCount {
                expected: 16,
                got: 15
            })
        );
    }

    #[test]
    fn envelope_roundtrip() {
        let inner = sample_challenge().encode().unwrap();
        let env = Envelope {
            canonical_challenge: inner,
            verifier_signature: [7u8; 64],
        };
        let back = Envelope::decode(&env.encode().unwrap()).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_encode_rejects_empty_inner() {
        let env = Envelope {
            canonical_challenge: vec![],
            verifier_signature: [7u8; 64],
        };
        assert_eq!(env.encode(), Err(SchemaError::BadLength { key: 0 }));
    }

    #[test]
    fn envelope_rejects_bad_sig_len() {
        let env_bytes = {
            let entries = vec![
                (0u64, Value::Bytes(vec![1, 2, 3])),
                (1, Value::Text(VERIFIER_SIGNATURE_ALGORITHM.into())),
                (2, Value::Bytes(vec![0u8; 63])), // not 64
            ];
            cbor::encode(&Value::Map(entries))
        };
        assert_eq!(
            Envelope::decode(&env_bytes),
            Err(SchemaError::BadLength { key: 2 })
        );
    }

    #[test]
    fn response_roundtrip() {
        let r = Response {
            protocol_version: 1,
            request_id: [1u8; 16],
            iphone_device_id: [9u8; 16],
            signed_payload_hash: [8u8; 32],
            signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // format is checked in the crypto layer
        };
        let back = Response::decode(&r.encode().unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn response_encode_rejects_empty_signature() {
        let r = Response {
            protocol_version: 1,
            request_id: [1u8; 16],
            iphone_device_id: [9u8; 16],
            signed_payload_hash: [8u8; 32],
            signature: vec![],
        };
        assert_eq!(r.encode(), Err(SchemaError::BadLength { key: 6 }));
    }

    fn response_entries(sig: Vec<u8>) -> Vec<(u64, Value)> {
        vec![
            (0u64, Value::Text(MESSAGE_TYPE_RESPONSE.into())),
            (1, Value::Uint(1)),
            (2, Value::Bytes(vec![0u8; 16])),
            (3, Value::Bytes(vec![0u8; 16])),
            (4, Value::Bytes(vec![0u8; 32])),
            (5, Value::Text(SIGNATURE_ALGORITHM.into())),
            (6, Value::Bytes(sig)),
        ]
    }

    #[test]
    fn response_rejects_oversize_signature() {
        // A 73B signature is rejected first by layer A's max_bytes=72 (TooLarge). Both fail closed.
        let bytes = cbor::encode(&Value::Map(response_entries(vec![0u8; 73])));
        assert_eq!(
            Response::decode(&bytes),
            Err(SchemaError::Cbor(cbor::Error::TooLarge))
        );
    }

    #[test]
    fn response_rejects_empty_signature() {
        // An empty signature is BadLength in layer B.
        let bytes = cbor::encode(&Value::Map(response_entries(vec![])));
        assert_eq!(
            Response::decode(&bytes),
            Err(SchemaError::BadLength { key: 6 })
        );
    }
}
