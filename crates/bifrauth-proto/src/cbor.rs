//! BifrAuth deterministic CBOR — low-level layer (layer A: profile validity).
//!
//! Implements layer A (BifrAuth deterministic profile validity) of `spec/cbor-profile.md`.
//! Enforces canonicality by **scanning the incoming bytes directly**; no decode-then-reencode comparison.
//!
//! Constraints implemented (the structural part of profile §1/§2/§3):
//! - The allowed data model is only uint / bstr / tstr / map / null (reject negative, array, tag,
//!   float, bool, undefined, simple other than null, indefinite, and break).
//! - Definite length only; preferred serialization (shortest).
//! - Map keys are uint in strict ascending order (`prev < cur`), detecting order violations and duplicates at once.
//! - Nesting-depth limit (each message in this profile is a top-level map = 1).
//! - Check size limits when the length head is read (before copying).
//! - Reject trailing bytes / multiple top-level values. Validate UTF-8 for tstr.
//!
//! **Content** constraints such as text NFC / unassigned / control / bidi are handled in layer B
//! (text policy), in a separate module because they need Unicode data. This layer is structural canonicality only.
//!
//! **This module is `pub(crate)` (internal).** An `Ok` from [`scan_structure`] means only "structurally
//! canonical and valid UTF-8"; it is **not valid as an authentication input** (NFC/text policy + layer-B
//! schema are also required). Only the validated decoders/encoders of `crate::schema` are public.
//!
//! **Classification of forbidden majors:** major 1 (negative) / 4 (array) / 6 (tag) return
//! [`Error::ForbiddenMajor`] immediately upon reading the initial byte (without reading ai/body). So e.g.
//! `0x9f` (indefinite array) and `0xd8` (tag head) become `ForbiddenMajor` rather than
//! `IndefiniteLength`/`Truncated`. Both fail closed, so the accepted set is identical. The finer
//! sub-classification (indefinite/reserved/truncated) is guaranteed **only for allowed majors** (the
//! implementation's fixed well-formedness-then-type-reject ordering of profile §2).

/// Layer-A resource bounds (profile §3). The schema layer passes the real values.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum total input bytes.
    pub max_total: usize,
    /// Maximum nesting depth (top-level map = 1).
    pub max_depth: u32,
    /// Maximum bytes for one byte string.
    pub max_bytes: usize,
    /// Maximum bytes for one text string.
    pub max_text: usize,
    /// Maximum number of map entries.
    pub max_map_entries: usize,
}

impl Default for Limits {
    /// Loose general-purpose defaults. The schema layer overrides with strict per-message values.
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

/// Layer-A rejection reasons. Correspond to the profile's negative vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The head/body ended prematurely.
    Truncated,
    /// There are extra bytes after the top-level value (includes multiple top-level values).
    TrailingBytes,
    /// The integer / length head is non-shortest.
    NonShortestInt,
    /// indefinite-length（additional info 31、major 2..5）。
    IndefiniteLength,
    /// Reserved additional info (28..30).
    ReservedAdditionalInfo,
    /// A stray break (0xff).
    UnexpectedBreak,
    /// A disallowed major type (1=negative, 4=array, 6=tag).
    ForbiddenMajor(u8),
    /// A simple value other than null / bool / undefined / float.
    ForbiddenSimpleOrFloat,
    /// Encoding simple 0..=23 with 0xf8 (non-shortest).
    NonShortestSimple,
    /// simple 24..=255 (outside the allowlist; only null is allowed).
    OutOfAllowlistSimple,
    /// A map key is not a uint (major 0).
    NonUintMapKey,
    /// Map keys are not strictly ascending (an order violation or duplicate).
    UnorderedOrDuplicateKey,
    /// Nesting depth exceeded the limit.
    DepthExceeded,
    /// A size limit was exceeded (detected before copying).
    TooLarge,
    /// A text string is invalid UTF-8.
    InvalidUtf8,
}

/// A value in the allowed data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Null,
    /// A map. Entries are held with **ascending, unique** keys (scan enforces this; encode assumes it).
    Map(Vec<(u64, Value)>),
}

// ---- Encoding (canonical generation) ----

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
            // canonical: emit keys in ascending order (independent of the caller's order).
            // Internal contract: keys are unique; satisfied because schema encoders build 0..N-1.
            encode_head(out, 5, entries.len() as u64);
            let mut idx: Vec<usize> = (0..entries.len()).collect();
            idx.sort_by_key(|&i| entries[i].0);
            // An assert that is active in release too. Since schema encoders build unique keys 0..N-1,
            // this invariant never fires in normal flow. Silently deduping would produce non-canonical output, so panic instead.
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

/// Encode a value into canonical CBOR bytes.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(&mut out, v);
    out
}

// ---- Scanning (direct canonicality check of incoming bytes + value reconstruction) ----

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

    /// Read the argument (value or length) of major 0/2/3/5 with shortest-form enforcement.
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
            _ => unreachable!("ai is 5 bits"),
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
            _ => unreachable!("major is 3 bits"),
        }
    }

    /// Check the length against the limit and remaining bytes before copying.
    fn checked_len(&self, len: u64, field_max: usize) -> Result<usize, Error> {
        let n = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        if n > field_max {
            return Err(Error::TooLarge);
        }
        // Reject a declared length that exceeds the remaining bytes here (before allocation).
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
        // Each entry is at least 2 bytes (uint key + 1-byte value). A coarse lower-bound check before allocation.
        if count.checked_mul(2).ok_or(Error::TooLarge)? > self.buf.len() - self.pos {
            return Err(Error::Truncated);
        }
        let mut entries: Vec<(u64, Value)> = Vec::with_capacity(count);
        let mut prev: Option<u64> = None;
        for _ in 0..count {
            // Keys are uint (major 0) only.
            let kb = self.next_byte()?;
            if kb >> 5 != 0 {
                return Err(Error::NonUintMapKey);
            }
            let key = self.read_arg(kb & 0x1f)?;
            // Strict ascending = detect order violations and duplicates at once.
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
            0..=19 => Err(Error::ForbiddenSimpleOrFloat), // direct simple 0..19 (other than null)
            24 => {
                // 0xf8 xx. simple 0..23 is non-shortest; 24..255 is outside the allowlist (distinct reasons).
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
            _ => unreachable!("ai is 5 bits"),
        }
    }
}

/// Scan the incoming bytes under the **layer-A structural rules** and return a `Value` if
/// structurally canonical (internal API).
///
/// This covers structural canonicality and UTF-8 validity only; it **excludes text NFC/unassigned and
/// the layer-B schema**. So an `Ok` does not mean "valid as an authentication input" — use it only via
/// the higher-level `schema` decoders. Rejects trailing bytes (including multiple top-level values).
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
        // Even if the input order is descending, encode sorts ascending and scan can reconstruct it.
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
        // Represent 24 with the non-shortest 0x19 0x00 0x18 instead of the shortest 2-byte 0x18 0x18.
        assert_eq!(
            scan_structure(&[0x19, 0x00, 0x18], limits()),
            Err(Error::NonShortestInt)
        );
        // 0 as 0x18 0x00 (non-shortest; 0x00 is shortest)
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
        // stray break
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
        // 0xf8 0x00 : simple 0 in 1-byte form (non-shortest)
        assert_eq!(
            scan_structure(&[0xf8, 0x00], limits()),
            Err(Error::NonShortestSimple)
        );
        // 0xf8 0xff : simple 255 (outside the allowlist)
        assert_eq!(
            scan_structure(&[0xf8, 0xff], limits()),
            Err(Error::OutOfAllowlistSimple)
        );
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut enc = encode(&Value::Uint(1));
        enc.push(0x01); // extra top-level
        assert_eq!(scan_structure(&enc, limits()), Err(Error::TrailingBytes));
    }

    #[test]
    fn reject_unordered_and_duplicate_keys() {
        // {1:0, 0:0} order violation
        assert_eq!(
            scan_structure(&[0xa2, 0x01, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
        // {0:0, 0:0} duplicate
        assert_eq!(
            scan_structure(&[0xa2, 0x00, 0x00, 0x00, 0x00], limits()),
            Err(Error::UnorderedOrDuplicateKey)
        );
    }

    #[test]
    fn reject_non_uint_map_key() {
        // {"a":0} text key
        assert_eq!(
            scan_structure(&[0xa1, 0x61, b'a', 0x00], limits()),
            Err(Error::NonUintMapKey)
        );
    }

    #[test]
    fn reject_depth_exceeded() {
        // With max_depth=1, a map whose value is a map (depth 2): {0:{}}
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
        // bstr length 5 (0x45 = major2, len5) but the limit is 4
        assert_eq!(
            scan_structure(&[0x45, 1, 2, 3, 4, 5], l),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn reject_declared_len_beyond_input() {
        // bstr length 10 but the body is short -> Truncated before allocation
        assert_eq!(
            scan_structure(&[0x4a, 1, 2, 3], limits()),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn reject_invalid_utf8() {
        // tstr length 1, body 0xff is invalid UTF-8
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

/// Additional tests (codex mid-review round 1, items 4-8): byte-exact table, non-shortest per ai,
/// length-head boundaries, truncated, all simple/forbidden classes, map boundaries, fuzz smoke / roundtrip.
#[cfg(test)]
mod boundary_tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn uint_encoding_is_byte_exact() {
        // (value, expected bytes). RFC 8949 preferred serialization.
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
        // A value that fits a one-size-smaller representation for each ai -> NonShortestInt.
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
        // A 24-byte bstr is shortest as 0x58 0x18. 0x58 0x17 (length 23 in 1-byte form) is non-shortest.
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
        // ai27 = u64::MAX as a bstr length -> exceeds the limit (TooLarge). No allocation.
        assert_eq!(
            scan_structure(
                &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                limits()
            ),
            Err(Error::TooLarge)
        );
        // map count = u64::MAX -> exceeds the limit.
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
        // 0x9f is major4 (array). Arrays are rejected immediately at the initial byte (before indefinite).
        assert_eq!(
            scan_structure(&[0x9f], limits()),
            Err(Error::ForbiddenMajor(4))
        );
        // 0xd8 is a major6 (tag) head. Tags are rejected immediately (before truncated).
        assert_eq!(
            scan_structure(&[0xd8], limits()),
            Err(Error::ForbiddenMajor(6))
        );
    }

    #[test]
    fn break_inside_map_value() {
        // {0: <break>} -> 0xff at the value position.
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
        // {24-form(0): 0} the key head is non-shortest.
        assert_eq!(
            scan_structure(&[0xa1, 0x18, 0x00, 0x00], limits()),
            Err(Error::NonShortestInt)
        );
    }

    #[test]
    fn map_key_order_boundary_23_24() {
        // {23:0, 24:0} ascending OK.
        let ok = [0xa2, 0x17, 0x00, 0x18, 0x18, 0x00];
        assert_eq!(
            scan_structure(&ok, limits()),
            Ok(Value::Map(vec![(23, Value::Uint(0)), (24, Value::Uint(0))]))
        );
        // {24:0, 23:0} reversed -> rejected.
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
        // 2 entries OK.
        assert!(scan_structure(&[0xa2, 0x00, 0x00, 0x01, 0x00], l).is_ok());
        // 3 entries -> TooLarge.
        assert_eq!(
            scan_structure(&[0xa3, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00], l),
            Err(Error::TooLarge)
        );
    }

    #[test]
    #[should_panic(expected = "map keys must be unique")]
    fn encode_duplicate_key_panics_in_all_profiles() {
        // An internal-contract violation (duplicate keys) is detected in all build profiles (does not silently dedup).
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
        // Brute-force 1-3 bytes and, when Ok, check that encode(decoded) equals the input.
        // Ensures the fixed-point property of structural canonicality (scan never returns Ok for non-canonical).
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
