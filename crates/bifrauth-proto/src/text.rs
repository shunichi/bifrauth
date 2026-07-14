//! Shared text content policy (profile §7/§7.1).
//!
//! This is the single source of truth for BifrAuth text-field acceptance, reused by every
//! canonical-CBOR schema in the workspace (the iPhone wire messages in [`crate::schema`] and the
//! local IPC messages in `bifrauth-ipc`). Keeping one implementation guarantees a single acceptance
//! set for text across all message families.
//!
//! Checks: byte-length range, ASCII-only (when specified), rejection of C0 (U+0000..U+001F, incl. NUL) /
//! C1 (U+0080..U+009F) control and Bidi_Control code points, **rejection of Unicode 16.0 unassigned (Cn)**,
//! and a **check that the text is in NFC normalized form**.
//!
//! NFC/unassigned must agree between Rust and Swift on the acceptance set (§7.1):
//! - The unassigned check uses the vendored Unicode 16.0 Cn table ([`crate::unicode_cn`]), not a library
//!   category table. **Reject 16.0-unassigned first**, then check NFC.
//! - The NFC check compares the NFC transform of the latest-stable `unicode-normalization` scalar-by-scalar
//!   (not via `==`). Since we have gated to 16.0-assigned, normalization stability makes the result match
//!   16.0 even on newer Unicode versions.

use crate::unicode_cn;
use unicode_normalization::UnicodeNormalization;

/// A text-policy violation, key-agnostic (callers attach their own field key for error reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextViolation {
    /// Byte length outside the allowed `min..=max`.
    BadLength,
    /// ASCII-only was required and a non-ASCII char was present, or a forbidden control/bidi char.
    Forbidden,
    /// A Unicode 16.0 unassigned (Cn) code point.
    Unassigned,
    /// Not in NFC normalized form.
    NotNfc,
}

// Bidi_Control=Yes (Unicode 16.0): ALM, LRM, RLM, LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
const BIDI_CONTROL: [u32; 12] = [
    0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
];

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
pub fn check(s: &str, min: usize, max: usize, ascii_only: bool) -> Result<(), TextViolation> {
    let len = s.len();
    if len < min || len > max {
        return Err(TextViolation::BadLength);
    }
    for ch in s.chars() {
        if ascii_only && !ch.is_ascii() {
            return Err(TextViolation::Forbidden);
        }
        if forbidden_char(ch) {
            return Err(TextViolation::Forbidden);
        }
        // Reject unassigned (16.0 Cn) before the NFC check (to satisfy the stability precondition).
        if unicode_cn::is_cn(ch as u32) {
            return Err(TextViolation::Unassigned);
        }
    }
    if !is_nfc(s) {
        return Err(TextViolation::NotNfc);
    }
    Ok(())
}
