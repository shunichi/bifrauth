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
            encode_head(out, 5, entries.len() as u64);
            // canonical: キー昇順で出力する（呼び出し側の順序に依存しない）。
            let mut idx: Vec<usize> = (0..entries.len()).collect();
            idx.sort_by_key(|&i| entries[i].0);
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
                && key <= p {
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

/// 受信バイト列を層A の規則で走査し、canonical であれば `Value` を返す。
/// trailing bytes（複数 top-level を含む）は拒否する。
pub fn scan(buf: &[u8], limits: Limits) -> Result<Value, Error> {
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
            let dec = scan(&enc, limits()).expect("scan ok");
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
        let dec = scan(&enc, limits()).unwrap();
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
            scan(&[0x19, 0x00, 0x18], limits()),
            Err(Error::NonShortestInt)
        );
        // 0 を 0x18 0x00（非最短、0x00 が最短）
        assert_eq!(scan(&[0x18, 0x00], limits()), Err(Error::NonShortestInt));
    }

    #[test]
    fn reject_indefinite_and_break() {
        // indefinite byte string (0x5f)
        assert_eq!(scan(&[0x5f, 0xff], limits()), Err(Error::IndefiniteLength));
        // 単独 break
        assert_eq!(scan(&[0xff], limits()), Err(Error::UnexpectedBreak));
    }

    #[test]
    fn reject_reserved_ai() {
        assert_eq!(scan(&[0x1c], limits()), Err(Error::ReservedAdditionalInfo)); // major0 ai28
    }

    #[test]
    fn reject_forbidden_majors() {
        assert_eq!(scan(&[0x20], limits()), Err(Error::ForbiddenMajor(1))); // -1
        assert_eq!(scan(&[0x80], limits()), Err(Error::ForbiddenMajor(4))); // array(0)
        assert_eq!(scan(&[0xc0], limits()), Err(Error::ForbiddenMajor(6))); // tag
    }

    #[test]
    fn reject_bool_undefined_float() {
        assert_eq!(scan(&[0xf4], limits()), Err(Error::ForbiddenSimpleOrFloat)); // false
        assert_eq!(scan(&[0xf5], limits()), Err(Error::ForbiddenSimpleOrFloat)); // true
        assert_eq!(scan(&[0xf7], limits()), Err(Error::ForbiddenSimpleOrFloat)); // undefined
        assert_eq!(
            scan(&[0xfa, 0, 0, 0, 0], limits()),
            Err(Error::ForbiddenSimpleOrFloat)
        ); // f32
    }

    #[test]
    fn null_accepted() {
        assert_eq!(scan(&[0xf6], limits()), Ok(Value::Null));
    }

    #[test]
    fn simple_f8_distinguishes_reasons() {
        // 0xf8 0x00 : simple 0 を 1 バイト形式で（非最短）
        assert_eq!(scan(&[0xf8, 0x00], limits()), Err(Error::NonShortestSimple));
        // 0xf8 0xff : simple 255（allowlist 外）
        assert_eq!(
            scan(&[0xf8, 0xff], limits()),
            Err(Error::OutOfAllowlistSimple)
        );
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut enc = encode(&Value::Uint(1));
        enc.push(0x01); // 余剰 top-level
        assert_eq!(scan(&enc, limits()), Err(Error::TrailingBytes));
    }

    #[test]
    fn reject_unordered_and_duplicate_keys() {
        // {1:0, 0:0} 昇順違反
        assert_eq!(
            scan(&[0xa2, 0x01, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
        // {0:0, 0:0} 重複
        assert_eq!(
            scan(&[0xa2, 0x00, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
    }

    #[test]
    fn reject_non_uint_map_key() {
        // {"a":0} テキストキー
        assert_eq!(
            scan(&[0xa1, 0x61, b'a', 0x00], limits()),
            Err(Error::NonUintMapKey)
        );
    }

    #[test]
    fn reject_depth_exceeded() {
        // max_depth=1 で map の値が map（depth2）: {0:{}}
        assert_eq!(
            scan(&[0xa1, 0x00, 0xa0], limits()),
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
        assert_eq!(scan(&[0x45, 1, 2, 3, 4, 5], l), Err(Error::TooLarge));
    }

    #[test]
    fn reject_declared_len_beyond_input() {
        // bstr 長 10 だが本体が足りない → 確保前に Truncated
        assert_eq!(scan(&[0x4a, 1, 2, 3], limits()), Err(Error::Truncated));
    }

    #[test]
    fn reject_invalid_utf8() {
        // tstr 長1、本体 0xff は不正 UTF-8
        assert_eq!(scan(&[0x61, 0xff], limits()), Err(Error::InvalidUtf8));
    }

    #[test]
    fn reject_total_too_large() {
        let l = Limits {
            max_total: 1,
            ..limits()
        };
        assert_eq!(scan(&[0x00, 0x00], l), Err(Error::TooLarge));
    }
}
