//! BifrAuth deterministic CBOR — 低レベル層（層A: プロファイル妥当性）。
//!
//! `spec/cbor-profile.md` の層A（BifrAuth deterministic profile validity）を実装する。
//! 受信バイト列を**直接走査**して canonicality を強制し、decode→再encode 比較はしない。
//!
//! 実装する制約（プロファイル §1・§2・§3 の構造部分）:
//! - 許可データモデルは uint / bstr / tstr / map / null のみ（negative・array・tag・float・
//!   bool・undefined・null 以外の simple・indefinite・break を拒否）。
//! - definite length のみ、preferred serialization（最短）。
//! - map キーは uint、strict 昇順（`prev < cur`）＝順序違反と重複を同時検出。
//! - ネスト深さ上限（本プロファイルの各メッセージは top-level map=1）。
//! - サイズ上限を長さ head を読んだ時点で（コピー前に）検査。
//! - trailing bytes / 複数 top-level を拒否。tstr は UTF-8 妥当性を検査。
//!
//! テキストの NFC / 未割当 / 制御・bidi などの**内容**制約は層B（テキストポリシー）で扱う
//! （Unicode データを要するため別モジュール）。ここは構造 canonicality に限定する。
//!
//! **本モジュールは `pub(crate)`（内部）。** [`scan_structure`] の `Ok` は「構造 canonical かつ
//! UTF-8 妥当」までを意味し、**認証入力として妥当ではない**（NFC/テキストポリシー + 層B スキーマが
//! 別途必要）。外部公開は `crate::schema` の検証済みデコーダ/エンコーダのみ。
//!
//! **禁止 major の分類:** major 1（negative）/ 4（array）/ 6（tag）は初期バイトを読んだ時点で
//! 即 [`Error::ForbiddenMajor`] を返す（ai/body を読まない）。よって例えば `0x9f`（indefinite array）や
//! `0xd8`（tag head）は `IndefiniteLength`/`Truncated` ではなく `ForbiddenMajor` になる。いずれも
//! fail closed で受理集合は同一。詳細な下位分類（indefinite/reserved/truncated）は**許可 major に
//! 対してのみ**保証する（プロファイル §2 の well-formedness→型拒否順の実装上の確定）。

/// 層A のリソース境界（プロファイル §3）。スキーマ層が実値を渡す。
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// 入力全体の最大バイト数。
    pub max_total: usize,
    /// 最大ネスト深さ（top-level map = 1）。
    pub max_depth: u32,
    /// byte string 1 個の最大バイト数。
    pub max_bytes: usize,
    /// text string 1 個の最大バイト数。
    pub max_text: usize,
    /// map の最大エントリ数。
    pub max_map_entries: usize,
}

impl Default for Limits {
    /// 汎用の緩い既定値。スキーマ層はメッセージごとの厳密値で上書きする。
    fn default() -> Self {
        Limits {
            max_total: 8 * 1024,
            max_depth: 1,
            max_bytes: 4 * 1024,
            max_text: 4 * 1024,
            max_map_entries: 64,
        }
    }
}

/// 層A の拒否理由。プロファイルの negative ベクタと対応する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// head/body が途中で終端した。
    Truncated,
    /// top-level 値の後に余剰バイトがある（複数 top-level を含む）。
    TrailingBytes,
    /// integer / length head が非最短表現。
    NonShortestInt,
    /// indefinite-length（additional info 31、major 2..5）。
    IndefiniteLength,
    /// 予約された additional info（28..30）。
    ReservedAdditionalInfo,
    /// 単独の break（0xff）。
    UnexpectedBreak,
    /// 許可外の major type（1=negative, 4=array, 6=tag）。
    ForbiddenMajor(u8),
    /// null 以外の simple / bool / undefined / float。
    ForbiddenSimpleOrFloat,
    /// simple 0..=23 を 0xf8 で符号化（非最短）。
    NonShortestSimple,
    /// simple 24..=255（allowlist 外。null のみ許可）。
    OutOfAllowlistSimple,
    /// map キーが uint(major 0) でない。
    NonUintMapKey,
    /// map キーが strict 昇順でない（順序違反または重複）。
    UnorderedOrDuplicateKey,
    /// ネスト深さが上限を超えた。
    DepthExceeded,
    /// サイズ上限超過（コピー前に検出）。
    TooLarge,
    /// text string が不正な UTF-8。
    InvalidUtf8,
}

/// 許可データモデルの値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Null,
    /// map。エントリは**昇順・一意**なキーで保持する（scan はこれを強制、encode は前提とする）。
    Map(Vec<(u64, Value)>),
}

// ---- エンコード（canonical 生成） ----

fn encode_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | (arg as u8));
    } else if arg <= 0xff {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Uint(n) => encode_head(out, 0, *n),
        Value::Bytes(b) => {
            encode_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            encode_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Null => out.push(0xf6),
        Value::Map(entries) => {
            // canonical: キー昇順で出力する（呼び出し側の順序に依存しない）。
            // 内部契約: キーは一意。schema エンコーダが 0..N-1 を構築するので満たされる。
            // duplicate を黙って落とさず、debug ビルドで検出する（非 canonical 出力の防止）。
            encode_head(out, 5, entries.len() as u64);
            let mut idx: Vec<usize> = (0..entries.len()).collect();
            idx.sort_by_key(|&i| entries[i].0);
            // release でも有効な assert。schema エンコーダは 0..N-1 の一意キーを構築するため
            // 通常フローで発火しない不変条件。黙って dedup すると非 canonical 出力になるため panic で防ぐ。
            assert!(
                idx.windows(2).all(|w| entries[w[0]].0 < entries[w[1]].0),
                "encode: map keys must be unique and this crate must only encode schema-built maps",
            );
            for &i in &idx {
                encode_head(out, 0, entries[i].0);
                encode_value(out, &entries[i].1);
            }
        }
    }
}

/// 値を canonical CBOR バイト列へエンコードする。
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(&mut out, v);
    out
}

// ---- スキャン（受信バイト列の直接 canonicality 検査 + 値の復元） ----

struct Scanner<'a> {
    buf: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl<'a> Scanner<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::TooLarge)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn next_byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// major 0/2/3/5 の引数（値または長さ）を最短強制で読む。
    fn read_arg(&mut self, ai: u8) -> Result<u64, Error> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => {
                let v = self.next_byte()? as u64;
                if v < 24 {
                    return Err(Error::NonShortestInt);
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= 0xff {
                    return Err(Error::NonShortestInt);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(Error::NonShortestInt);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= 0xffff_ffff {
                    return Err(Error::NonShortestInt);
                }
                Ok(v)
            }
            28..=30 => Err(Error::ReservedAdditionalInfo),
            31 => Err(Error::IndefiniteLength),
            _ => unreachable!("ai は 5bit"),
        }
    }

    fn read_value(&mut self, depth: u32) -> Result<Value, Error> {
        let ib = self.next_byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.read_arg(ai)?)),
            1 => Err(Error::ForbiddenMajor(1)), // negative integer
            2 => {
                let len = self.read_arg(ai)?;
                let n = self.checked_len(len, self.limits.max_bytes)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let len = self.read_arg(ai)?;
                let n = self.checked_len(len, self.limits.max_text)?;
                let bytes = self.take(n)?;
                let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => Err(Error::ForbiddenMajor(4)), // array
            5 => self.read_map(ai, depth),
            6 => Err(Error::ForbiddenMajor(6)), // tag
            7 => self.read_simple(ai),
            _ => unreachable!("major は 3bit"),
        }
    }

    /// 長さを上限と残バイトに対しコピー前に検査する。
    fn checked_len(&self, len: u64, field_max: usize) -> Result<usize, Error> {
        let n = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        if n > field_max {
            return Err(Error::TooLarge);
        }
        // 残バイトを超える宣言長はここで弾く（確保前）。
        if n > self.buf.len() - self.pos {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    fn read_map(&mut self, ai: u8, depth: u32) -> Result<Value, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::DepthExceeded);
        }
        let count_u = self.read_arg(ai)?;
        let count = usize::try_from(count_u).map_err(|_| Error::TooLarge)?;
        if count > self.limits.max_map_entries {
            return Err(Error::TooLarge);
        }
        // 各エントリは最低 2 バイト（uint key + 1 バイト値）。確保前の粗い下限検査。
        if count.checked_mul(2).ok_or(Error::TooLarge)? > self.buf.len() - self.pos {
            return Err(Error::Truncated);
        }
        let mut entries: Vec<(u64, Value)> = Vec::with_capacity(count);
        let mut prev: Option<u64> = None;
        for _ in 0..count {
            // キーは uint(major 0) のみ。
            let kb = self.next_byte()?;
            if kb >> 5 != 0 {
                return Err(Error::NonUintMapKey);
            }
            let key = self.read_arg(kb & 0x1f)?;
            // strict 昇順 = 順序違反と重複を同時に検出。
            if let Some(p) = prev
                && key <= p
            {
                return Err(Error::UnorderedOrDuplicateKey);
            }
            prev = Some(key);
            let val = self.read_value(depth + 1)?;
            entries.push((key, val));
        }
        Ok(Value::Map(entries))
    }

    fn read_simple(&mut self, ai: u8) -> Result<Value, Error> {
        match ai {
            22 => Ok(Value::Null),                              // 0xf6
            20 | 21 | 23 => Err(Error::ForbiddenSimpleOrFloat), // false/true/undefined
            0..=19 => Err(Error::ForbiddenSimpleOrFloat),       // 直接 simple 0..19（null 以外）
            24 => {
                // 0xf8 xx。simple 0..23 は非最短、24..255 は allowlist 外（理由を分離）。
                let v = self.next_byte()?;
                if v < 24 {
                    Err(Error::NonShortestSimple)
                } else {
                    Err(Error::OutOfAllowlistSimple)
                }
            }
            25..=27 => Err(Error::ForbiddenSimpleOrFloat), // float16/32/64
            28..=30 => Err(Error::ReservedAdditionalInfo),
            31 => Err(Error::UnexpectedBreak),
            _ => unreachable!("ai は 5bit"),
        }
    }
}

/// 受信バイト列を**層Aの構造規則**で走査し、構造 canonical なら `Value` を返す（内部 API）。
///
/// これは構造 canonicality と UTF-8 妥当性までで、**テキストの NFC/未割当や層B スキーマは含まない**。
/// したがって `Ok` は「認証入力として妥当」を意味しない — 上位の `schema` デコーダ経由でのみ用いる。
/// trailing bytes（複数 top-level を含む）は拒否する。
pub fn scan_structure(buf: &[u8], limits: Limits) -> Result<Value, Error> {
    if buf.len() > limits.max_total {
        return Err(Error::TooLarge);
    }
    let mut s = Scanner {
        buf,
        pos: 0,
        limits,
    };
    let v = s.read_value(1)?;
    if s.pos != buf.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    fn map(entries: Vec<(u64, Value)>) -> Value {
        Value::Map(entries)
    }

    #[test]
    fn roundtrip_scalars() {
        for v in [
            Value::Uint(0),
            Value::Uint(23),
            Value::Uint(24),
            Value::Uint(255),
            Value::Uint(256),
            Value::Uint(65_535),
            Value::Uint(65_536),
            Value::Uint(u32::MAX as u64),
            Value::Uint(u32::MAX as u64 + 1),
            Value::Uint(u64::MAX),
            Value::Bytes(vec![]),
            Value::Bytes(vec![1, 2, 3]),
            Value::Text(String::new()),
            Value::Text("bifrauth".to_string()),
            Value::Null,
        ] {
            let enc = encode(&v);
            let dec = scan_structure(&enc, limits()).expect("scan ok");
            assert_eq!(v, dec, "roundtrip {v:?}");
        }
    }

    #[test]
    fn roundtrip_map_sorts_keys() {
        // 入力順が降順でも encode は昇順に並べ、scan で復元できる。
        let v = map(vec![
            (15, Value::Text("c".into())),
            (0, Value::Uint(1)),
            (7, Value::Null),
        ]);
        let enc = encode(&v);
        let dec = scan_structure(&enc, limits()).unwrap();
        assert_eq!(
            dec,
            map(vec![
                (0, Value::Uint(1)),
                (7, Value::Null),
                (15, Value::Text("c".into())),
            ])
        );
    }

    #[test]
    fn reject_non_shortest_uint() {
        // 24 を 2 バイト（0x18 0x18 が最短）ではなく非最短の 0x19 0x00 0x18 で表す。
        assert_eq!(
            scan_structure(&[0x19, 0x00, 0x18], limits()),
            Err(Error::NonShortestInt)
        );
        // 0 を 0x18 0x00（非最短、0x00 が最短）
        assert_eq!(
            scan_structure(&[0x18, 0x00], limits()),
            Err(Error::NonShortestInt)
        );
    }

    #[test]
    fn reject_indefinite_and_break() {
        // indefinite byte string (0x5f)
        assert_eq!(
            scan_structure(&[0x5f, 0xff], limits()),
            Err(Error::IndefiniteLength)
        );
        // 単独 break
        assert_eq!(
            scan_structure(&[0xff], limits()),
            Err(Error::UnexpectedBreak)
        );
    }

    #[test]
    fn reject_reserved_ai() {
        assert_eq!(
            scan_structure(&[0x1c], limits()),
            Err(Error::ReservedAdditionalInfo)
        ); // major0 ai28
    }

    #[test]
    fn reject_forbidden_majors() {
        assert_eq!(
            scan_structure(&[0x20], limits()),
            Err(Error::ForbiddenMajor(1))
        ); // -1
        assert_eq!(
            scan_structure(&[0x80], limits()),
            Err(Error::ForbiddenMajor(4))
        ); // array(0)
        assert_eq!(
            scan_structure(&[0xc0], limits()),
            Err(Error::ForbiddenMajor(6))
        ); // tag
    }

    #[test]
    fn reject_bool_undefined_float() {
        assert_eq!(
            scan_structure(&[0xf4], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // false
        assert_eq!(
            scan_structure(&[0xf5], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // true
        assert_eq!(
            scan_structure(&[0xf7], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // undefined
        assert_eq!(
            scan_structure(&[0xfa, 0, 0, 0, 0], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // f32
    }

    #[test]
    fn null_accepted() {
        assert_eq!(scan_structure(&[0xf6], limits()), Ok(Value::Null));
    }

    #[test]
    fn simple_f8_distinguishes_reasons() {
        // 0xf8 0x00 : simple 0 を 1 バイト形式で（非最短）
        assert_eq!(
            scan_structure(&[0xf8, 0x00], limits()),
            Err(Error::NonShortestSimple)
        );
        // 0xf8 0xff : simple 255（allowlist 外）
        assert_eq!(
            scan_structure(&[0xf8, 0xff], limits()),
            Err(Error::OutOfAllowlistSimple)
        );
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut enc = encode(&Value::Uint(1));
        enc.push(0x01); // 余剰 top-level
        assert_eq!(scan_structure(&enc, limits()), Err(Error::TrailingBytes));
    }

    #[test]
    fn reject_unordered_and_duplicate_keys() {
        // {1:0, 0:0} 昇順違反
        assert_eq!(
            scan_structure(&[0xa2, 0x01, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
        // {0:0, 0:0} 重複
        assert_eq!(
            scan_structure(&[0xa2, 0x00, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
    }

    #[test]
    fn reject_non_uint_map_key() {
        // {"a":0} テキストキー
        assert_eq!(
            scan_structure(&[0xa1, 0x61, b'a', 0x00], limits()),
            Err(Error::NonUintMapKey)
        );
    }

    #[test]
    fn reject_depth_exceeded() {
        // max_depth=1 で map の値が map（depth2）: {0:{}}
        assert_eq!(
            scan_structure(&[0xa1, 0x00, 0xa0], limits()),
            Err(Error::DepthExceeded)
        );
    }

    #[test]
    fn reject_oversize_before_alloc() {
        let l = Limits {
            max_bytes: 4,
            ..limits()
        };
        // bstr 長 5（0x45 = major2, len5）だが上限4
        assert_eq!(
            scan_structure(&[0x45, 1, 2, 3, 4, 5], l),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn reject_declared_len_beyond_input() {
        // bstr 長 10 だが本体が足りない → 確保前に Truncated
        assert_eq!(
            scan_structure(&[0x4a, 1, 2, 3], limits()),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn reject_invalid_utf8() {
        // tstr 長1、本体 0xff は不正 UTF-8
        assert_eq!(
            scan_structure(&[0x61, 0xff], limits()),
            Err(Error::InvalidUtf8)
        );
    }

    #[test]
    fn reject_total_too_large() {
        let l = Limits {
            max_total: 1,
            ..limits()
        };
        assert_eq!(scan_structure(&[0x00, 0x00], l), Err(Error::TooLarge));
    }

    #[test]
    fn accepts_total_at_exact_boundary() {
        let l = Limits {
            max_total: 1,
            ..limits()
        };
        assert_eq!(scan_structure(&[0x00], l), Ok(Value::Uint(0)));
    }

    #[test]
    fn empty_input_is_truncated() {
        assert_eq!(scan_structure(&[], limits()), Err(Error::Truncated));
    }
}

/// 追加テスト（codex 中間レビュー 第1巡 指摘4〜8）: バイト厳密 table、非最短各 ai、
/// 長さ head 境界、truncated、simple/forbidden 全分類、map 境界、fuzz smoke / roundtrip。
#[cfg(test)]
mod boundary_tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn uint_encoding_is_byte_exact() {
        // (値, 期待バイト列)。RFC 8949 preferred serialization。
        let cases: &[(u64, &[u8])] = &[
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65_535, &[0x19, 0xff, 0xff]),
            (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (u32::MAX as u64, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (
                u32::MAX as u64 + 1,
                &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                u64::MAX,
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (val, bytes) in cases {
            assert_eq!(&encode(&Value::Uint(*val)), bytes, "encode {val}");
            assert_eq!(
                scan_structure(bytes, limits()),
                Ok(Value::Uint(*val)),
                "scan {val}"
            );
        }
    }

    #[test]
    fn non_shortest_per_ai_rejected() {
        // 各 ai で 1 段小さい表現に収まる値 → NonShortestInt。
        assert_eq!(
            scan_structure(&[0x18, 0x17], limits()),
            Err(Error::NonShortestInt)
        ); // 23 in ai24
        assert_eq!(
            scan_structure(&[0x19, 0x00, 0xff], limits()),
            Err(Error::NonShortestInt)
        ); // 255 in ai25
        assert_eq!(
            scan_structure(&[0x1a, 0x00, 0x00, 0xff, 0xff], limits()),
            Err(Error::NonShortestInt)
        ); // 65535 in ai26
        assert_eq!(
            scan_structure(
                &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
                limits()
            ),
            Err(Error::NonShortestInt)
        ); // u32::MAX in ai27
    }

    #[test]
    fn length_head_boundaries_for_bstr() {
        // 24 バイトの bstr は 0x58 0x18 が最短。0x58 0x17（長さ23の1バイト形式）は非最短。
        let mut ok = vec![0x58, 0x18];
        ok.extend_from_slice(&[0u8; 24]);
        assert_eq!(
            scan_structure(&ok, limits()),
            Ok(Value::Bytes(vec![0u8; 24]))
        );
        assert_eq!(
            scan_structure(&[0x58, 0x17], limits()),
            Err(Error::NonShortestInt)
        );
    }

    #[test]
    fn truncated_heads() {
        assert_eq!(scan_structure(&[0x18], limits()), Err(Error::Truncated)); // ai24 head
        assert_eq!(
            scan_structure(&[0x19, 0x01], limits()),
            Err(Error::Truncated)
        ); // ai25
        assert_eq!(
            scan_structure(&[0x1a, 0x00, 0x01], limits()),
            Err(Error::Truncated)
        ); // ai26
        assert_eq!(
            scan_structure(&[0x1b, 0x00], limits()),
            Err(Error::Truncated)
        ); // ai27
    }

    #[test]
    fn huge_declared_lengths_rejected_before_alloc() {
        // ai27 = u64::MAX を bstr 長として → 上限超過（TooLarge）。確保しない。
        assert_eq!(
            scan_structure(
                &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                limits()
            ),
            Err(Error::TooLarge)
        );
        // map count = u64::MAX → 上限超過。
        assert_eq!(
            scan_structure(
                &[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                limits()
            ),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn all_forbidden_simple_and_float() {
        assert_eq!(
            scan_structure(&[0xe0], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // simple 0
        assert_eq!(
            scan_structure(&[0xf3], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // simple 19
        assert_eq!(
            scan_structure(&[0xf8, 0x17], limits()),
            Err(Error::NonShortestSimple)
        ); // f8 23
        assert_eq!(
            scan_structure(&[0xf8, 0x18], limits()),
            Err(Error::OutOfAllowlistSimple)
        ); // f8 24
        assert_eq!(
            scan_structure(&[0xf9, 0x00, 0x00], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // f16
        assert_eq!(
            scan_structure(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // f64
    }

    #[test]
    fn reserved_ai_across_majors() {
        assert_eq!(
            scan_structure(&[0x1c], limits()),
            Err(Error::ReservedAdditionalInfo)
        ); // major0 ai28
        assert_eq!(
            scan_structure(&[0x5d], limits()),
            Err(Error::ReservedAdditionalInfo)
        ); // major2 ai29
        assert_eq!(
            scan_structure(&[0xbe], limits()),
            Err(Error::ReservedAdditionalInfo)
        ); // major5 ai30
    }

    #[test]
    fn indefinite_across_majors_and_array_precedence() {
        assert_eq!(
            scan_structure(&[0x1f], limits()),
            Err(Error::IndefiniteLength)
        ); // major0 ai31
        assert_eq!(
            scan_structure(&[0x5f], limits()),
            Err(Error::IndefiniteLength)
        ); // bstr*
        assert_eq!(
            scan_structure(&[0x7f], limits()),
            Err(Error::IndefiniteLength)
        ); // tstr*
        assert_eq!(
            scan_structure(&[0xbf], limits()),
            Err(Error::IndefiniteLength)
        ); // map*
        // 0x9f は major4(array)。array は初期バイトで即拒否（indefinite より先）。
        assert_eq!(
            scan_structure(&[0x9f], limits()),
            Err(Error::ForbiddenMajor(4))
        );
        // 0xd8 は major6(tag) head。tag は即拒否（truncated より先）。
        assert_eq!(
            scan_structure(&[0xd8], limits()),
            Err(Error::ForbiddenMajor(6))
        );
    }

    #[test]
    fn break_inside_map_value() {
        // {0: <break>} → 値位置の 0xff。
        assert_eq!(
            scan_structure(&[0xa1, 0x00, 0xff], limits()),
            Err(Error::UnexpectedBreak)
        );
    }

    #[test]
    fn empty_map_ok() {
        assert_eq!(scan_structure(&[0xa0], limits()), Ok(Value::Map(vec![])));
    }

    #[test]
    fn map_key_non_shortest_rejected() {
        // {24-form(0): 0} キー head が非最短。
        assert_eq!(
            scan_structure(&[0xa1, 0x18, 0x00, 0x00], limits()),
            Err(Error::NonShortestInt)
        );
    }

    #[test]
    fn map_key_order_boundary_23_24() {
        // {23:0, 24:0} 昇順 OK。
        let ok = [0xa2, 0x17, 0x00, 0x18, 0x18, 0x00];
        assert_eq!(
            scan_structure(&ok, limits()),
            Ok(Value::Map(vec![(23, Value::Uint(0)), (24, Value::Uint(0))]))
        );
        // {24:0, 23:0} 逆順 → 拒否。
        let bad = [0xa2, 0x18, 0x18, 0x00, 0x17, 0x00];
        assert_eq!(
            scan_structure(&bad, limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
    }

    #[test]
    fn map_entries_limit_boundary() {
        let l = Limits {
            max_map_entries: 2,
            ..limits()
        };
        // 2 エントリ OK。
        assert!(scan_structure(&[0xa2, 0x00, 0x00, 0x01, 0x00], l).is_ok());
        // 3 エントリ → TooLarge。
        assert_eq!(
            scan_structure(&[0xa3, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00], l),
            Err(Error::TooLarge)
        );
    }

    #[test]
    #[should_panic(expected = "map keys must be unique")]
    fn encode_duplicate_key_panics_in_all_profiles() {
        // 内部契約違反（重複キー）は debug ビルドで検出する（黙って dedup しない）。
        let v = Value::Map(vec![(0, Value::Uint(1)), (0, Value::Uint(2))]);
        let _ = encode(&v);
    }

    #[test]
    fn fuzz_smoke_all_single_bytes_no_panic() {
        for b in 0u16..=255 {
            let _ = scan_structure(&[b as u8], limits());
        }
    }

    #[test]
    fn ok_implies_canonical_reencode_roundtrip() {
        // 1〜3 バイトを総当りし、Ok なら encode(decoded) が入力と一致することを確認。
        // 構造 canonical の不動点性（scan は非 canonical を Ok にしない）を担保する。
        let mut buf = Vec::new();
        for a in 0u16..=255 {
            buf.clear();
            buf.push(a as u8);
            if let Ok(v) = scan_structure(&buf, limits()) {
                assert_eq!(encode(&v), buf, "1-byte {a:#x}");
            }
            for b in 0u16..=255 {
                buf.clear();
                buf.extend_from_slice(&[a as u8, b as u8]);
                if let Ok(v) = scan_structure(&buf, limits()) {
                    assert_eq!(encode(&v), buf, "2-byte {a:#x} {b:#x}");
                }
            }
        }
    }
}
