//! 層B: BifrAuth メッセージのスキーマ検証とエンコード。
//!
//! 規範は `spec/cbor-profile.md` §4（challenge.v1）/§5（response.v1）/§6（envelope.v1）。
//! 層A（[`crate::cbor`]）で canonical と判定された `Value` に対し、キー全必須・exact/範囲を検査する。
//! 各スキーマはキー 0..N-1 の連番 map なので、`cbor::scan_structure` が保証する「昇順・一意キー」と合わせ、
//! 「エントリ数 == N かつ i 番目のキー == i」で余分/欠損/重複/順序違反をまとめて排除する。
//!
//! **未実装（依存判断を保留）:** テキストの NFC 正規化検査と「未割当 code point 拒否」は
//! Unicode 16.0 のデータを要し、Rust/Swift の Unicode バージョン整合という相互運用上の判断が
//! 必要なため、本コミットでは行わない（[`TextPolicy`] のドキュメント参照）。ASCII・制御・bidi・
//! byte 長・exact/範囲は実装済み。

use crate::cbor::{self, Limits, Value};

/// 初版のプロトコルバージョン（プロファイル §10 の対応表）。
pub const PROTOCOL_VERSION: u64 = 1;

pub const MESSAGE_TYPE_CHALLENGE: &str = "bifrauth.challenge.v1";
pub const MESSAGE_TYPE_RESPONSE: &str = "bifrauth.response.v1";
pub const SIGNATURE_ALGORITHM: &str = "ECDSA_P256_SHA256_DER";
pub const VERIFIER_SIGNATURE_ALGORITHM: &str = "Ed25519";

const EPOCH_MAX: u64 = 253_402_300_799; // year 9999, < 2^53
const TTL_MIN: u64 = 1;
const TTL_MAX: u64 = 30;
const UID_MAX: u64 = 4_294_967_294; // (uid_t)-1 = 4294967295 を拒否

const CHALLENGE_MAX_TOTAL: usize = 4096;
const ENVELOPE_MAX_TOTAL: usize = 4608;
const RESPONSE_MAX_TOTAL: usize = 512;

// フィールド byte 上限（プロファイル §4/§5/§6）
const MAX_DEVICE_NAME: usize = 128;
const MAX_USERNAME: usize = 256;
const MAX_PAM_SERVICE: usize = 128;
const MAX_PAM_TTY_RHOST: usize = 256;
const MAX_REQUESTED_ACTION: usize = 256;
const MAX_DEVICE_ID_TEXT: usize = 128; // response.iphone_device_id は 16B bstr だが将来 hint 表示用の余地
const MAX_DER_SIGNATURE: usize = 72; // P-256 X9.62 DER の最大長

/// スキーマ検証の失敗理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// 層A（canonical）の失敗。
    Cbor(cbor::Error),
    /// top-level が map でない。
    NotMap,
    /// エントリ数が期待と異なる。
    WrongEntryCount { expected: usize, got: usize },
    /// i 番目のキーが期待（= i）と異なる（余分/欠損/順序）。
    WrongKey { pos: usize, expected: u64, got: u64 },
    /// フィールドの CBOR 型が異なる。
    WrongType { key: u64 },
    /// 数値が許可範囲外。
    OutOfRange { key: u64 },
    /// byte/text の長さが規定外。
    BadLength { key: u64 },
    /// テキストが ASCII/制御/bidi 制約に違反。
    BadText { key: u64 },
    /// `message_type` が一致しない。
    MessageTypeMismatch,
    /// 固定文字列フィールド（algorithm 等）が一致しない。
    FixedStringMismatch { key: u64 },
    /// TTL（expires - issued）が範囲外、または issued >= expires。
    TtlOutOfRange,
}

impl From<cbor::Error> for SchemaError {
    fn from(e: cbor::Error) -> Self {
        SchemaError::Cbor(e)
    }
}

/// テキストフィールドの内容ポリシー。
///
/// 実装済み: byte 長範囲、ASCII 限定（指定時）、C0（U+0000..U+001F, NUL 含む）/ C1
/// （U+0080..U+009F）制御と Bidi_Control code point の拒否。
///
/// **未実装（要依存判断）:** NFC 正規化検査と Unicode 16.0 UCD による未割当 code point 拒否。
/// これらは Unicode データを要し、Rust/Swift 双方が **同一 Unicode バージョン（16.0）** を用いる
/// ことが相互運用の前提になる。crate 選定（例 `unicode-normalization`）と Unicode バージョン整合を
/// 決めてから実装する（プロファイル §7）。
struct TextPolicy;

// Bidi_Control=Yes（Unicode 16.0）: ALM, LRM, RLM, LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
const BIDI_CONTROL: [u32; 12] = [
    0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
];

impl TextPolicy {
    fn forbidden_char(ch: char) -> bool {
        let c = ch as u32;
        // C0（NUL 含む）と C1 制御。
        if c <= 0x1f || (0x80..=0x9f).contains(&c) {
            return true;
        }
        BIDI_CONTROL.contains(&c)
    }

    /// byte 長 `min..=max`、必要なら ASCII 限定、制御・bidi 拒否を検査する。
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
        }
        Ok(())
    }
}

// ---- Value からの型付き取り出し ----

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

/// map として連番キー 0..N-1 を厳密に検査し、値スライスを返す。
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

/// `bifrauth.challenge.v1`（プロファイル §4）。
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
    /// 全フィールドの層B 制約を検査する（decode 後と encode 前の両方で必ず呼ぶ）。
    /// **暗黙の正規化はしない** — 違反は Err にする。
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(SchemaError::OutOfRange { key: 1 });
        }
        // exact byte 長は型（[u8; N]）が保証する。
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
        // confirmation_code: ASCII [0-9]{6} exact。
        if self.confirmation_code.len() != 6
            || !self.confirmation_code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(SchemaError::BadText { key: 15 });
        }
        Ok(())
    }

    /// canonical バイト列を検証して復元する（層A + 型抽出 + 層B `validate`）。
    pub fn decode(bytes: &[u8]) -> Result<Challenge, SchemaError> {
        let v = cbor::scan_structure(bytes, challenge_limits())?;
        let e = map_entries(&v, 16)?;

        // 型・exact byte 長・固定文字列の抽出（構造）。
        expect_fixed(&e[0].1, 0, MESSAGE_TYPE_CHALLENGE)?;
        let protocol_version = take_uint(&e[1].1, 1)?;
        let request_id = take_bytes_exact::<16>(&e[2].1, 2)?;
        let nonce = take_bytes_exact::<16>(&e[3].1, 3)?;
        let verifier_key_id = take_bytes_exact::<32>(&e[4].1, 4)?;
        let linux_device_id = take_bytes_exact::<16>(&e[5].1, 5)?;
        let linux_device_name = take_text(&e[6].1, 6)?.to_owned();
        // uid は u32 へ格納するため、範囲外はここで拒否してから構築する（validate でも再検査）。
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

    /// 検証してから canonical バイト列へエンコードする。不正な内容は Err（正規化しない）。
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

/// `bifrauth.envelope.v1`（プロファイル §6）。inner の canonical_challenge は生バイト列で保持する。
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
    /// 層B 制約: canonical_challenge は 1..=CHALLENGE_MAX_TOTAL バイト。
    /// verifier_signature の長さは型（[u8; 64]）が保証する。
    pub fn validate(&self) -> Result<(), SchemaError> {
        let len = self.canonical_challenge.len();
        if len == 0 || len > CHALLENGE_MAX_TOTAL {
            return Err(SchemaError::BadLength { key: 0 });
        }
        Ok(())
    }

    /// envelope を復元する。
    ///
    /// **重要（プロファイル §6・§8）:** 返る [`Envelope::canonical_challenge`] は**未検証の生バイト列**。
    /// これは「Ed25519 署名を生バイト列に対して検証する」設計のため意図的にそのまま保持する。
    /// 呼び出し側は必ず次を行う: (1) `verifier_signature` を登録済み verifier 公開鍵で
    /// `canonical_challenge` の**生バイト列**に対し検証 → (2) **同じバイト列**を
    /// [`Challenge::decode`] に通して層A/層B を検査 → (3) 保留中の request 状態（request_id/nonce/
    /// expiry 等）と照合。**decode しただけの `Envelope` を検証済み Challenge と誤認しないこと。**
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

    /// 検証してから canonical バイト列へエンコードする。
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

/// `bifrauth.response.v1`（プロファイル §5）。
///
/// 注意: `signed_payload_hash` は**認証入力として信用しない**。authd は保留 challenge から
/// 再計算し、不一致は malformed 扱い。署名検証は保存済み canonical bytes に対して行う（プロファイル §5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub protocol_version: u64,
    pub request_id: [u8; 16],
    pub iphone_device_id: [u8; 16],
    pub signed_payload_hash: [u8; 32],
    pub signature: Vec<u8>, // X9.62 DER, 1..=72B（strict DER 検査は crypto 層）
}

fn response_limits() -> Limits {
    Limits {
        max_total: RESPONSE_MAX_TOTAL,
        max_depth: 1,
        max_bytes: 72, // signature DER 上限
        max_text: MAX_DEVICE_ID_TEXT.max(SIGNATURE_ALGORITHM.len()),
        max_map_entries: 7,
    }
}

impl Response {
    /// 層B 制約: protocol_version==1、signature は 1..=72B（strict DER は crypto 層）。
    /// exact byte 長フィールドは型が保証する。
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

    /// 検証してから canonical バイト列へエンコードする。
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

    // encode は self を検証するので、不正な struct は encode() 時点で Err（正規化しない）。
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
        c.confirmation_code = "12345".into(); // 5 桁
        assert_eq!(c.encode(), Err(SchemaError::BadText { key: 15 }));
        c.confirmation_code = "12a456".into(); // 非数字
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
        // key0 を別文字列にした map を直接構築。
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
        // 15 エントリ（1 個欠損）。
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
                (2, Value::Bytes(vec![0u8; 63])), // 64 でない
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
            signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // 形式は crypto 層で検査
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
        // 73B 署名は層A の max_bytes=72 で先に弾かれる（TooLarge）。どちらも fail closed。
        let bytes = cbor::encode(&Value::Map(response_entries(vec![0u8; 73])));
        assert_eq!(
            Response::decode(&bytes),
            Err(SchemaError::Cbor(cbor::Error::TooLarge))
        );
    }

    #[test]
    fn response_rejects_empty_signature() {
        // 空署名は層B で BadLength。
        let bytes = cbor::encode(&Value::Map(response_entries(vec![])));
        assert_eq!(
            Response::decode(&bytes),
            Err(SchemaError::BadLength { key: 6 })
        );
    }
}
