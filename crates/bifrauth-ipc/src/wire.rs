//! The local IPC message schema (ipc-design §3/§4), PAM module ↔ verifier.
//!
//! These four messages reuse `bifrauth_proto`'s canonical-CBOR scanner and shared text policy, so the
//! acceptance representation is identical to the iPhone wire messages: definite-length, shortest-form,
//! ascending unique uint keys, no float/tag/bool/negative, strict per-field byte limits and UTF-8/NFC.
//! Each map is `{0: message_type, 1: ..., ...}` with contiguous keys `0..N`.
//!
//! Booleans are not part of the canonical profile (the scanner rejects CBOR `true`/`false`), so a flag
//! like `conversation_succeeded` and the bounded `OutcomeCode` are carried as `uint` and their value set
//! is checked here.

use bifrauth_proto::cbor::{self, Limits, Value};
use bifrauth_proto::text;

// ---- message type tags ----

pub const MT_AUTH_REQUEST: &str = "bifrauth.ipc.auth_request.v1";
pub const MT_CONFIRMATION_CODE: &str = "bifrauth.ipc.confirmation_code.v1";
pub const MT_DISPLAY_ACK: &str = "bifrauth.ipc.display_ack.v1";
pub const MT_OUTCOME: &str = "bifrauth.ipc.outcome.v1";

// ---- per-field byte limits (ipc-design §3,追補D). Kept in line with the proto profile. ----

const MAX_USERNAME: usize = 256;
const MAX_PAM_SERVICE: usize = 128;
const MAX_PAM_TTY_RHOST: usize = 256;
/// Upper bound for a message-type text (longest tag + slack); also the scanner's `max_text` per message.
const MAX_MESSAGE_TYPE: usize = 64;
const CONFIRMATION_CODE_LEN: usize = 6;
const REQUEST_ID_LEN: usize = 16;

// Tight per-message total-byte caps (all well under the 8 KiB frame cap).
const AUTH_REQUEST_MAX_TOTAL: usize = 1024;
const SMALL_MSG_MAX_TOTAL: usize = 256;

/// A schema violation. Key-bearing variants name the offending map key for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcSchemaError {
    /// Layer-A canonical CBOR rejection.
    Cbor(cbor::Error),
    /// The top-level value is not a map.
    NotMap,
    /// The map has the wrong number of entries.
    WrongEntryCount { expected: usize, got: usize },
    /// A key was missing / out of order (expected contiguous `0..N`).
    WrongKey { pos: usize, expected: u64, got: u64 },
    /// A field had the wrong CBOR type.
    WrongType { key: u64 },
    /// A field's value was out of its allowed range.
    OutOfRange { key: u64 },
    /// A byte/text length was out of range.
    BadLength { key: u64 },
    /// Text violated the ASCII/control/bidi policy.
    BadText { key: u64 },
    /// Text was not in NFC form.
    NotNfc { key: u64 },
    /// Text contained a Unicode 16.0 unassigned code point.
    Unassigned { key: u64 },
    /// The message-type tag (key 0) did not match the expected message.
    MessageTypeMismatch,
    /// The `OutcomeCode` uint was not a known value.
    UnknownOutcomeCode,
}

impl From<cbor::Error> for IpcSchemaError {
    fn from(e: cbor::Error) -> Self {
        IpcSchemaError::Cbor(e)
    }
}

fn check_text(
    s: &str,
    key: u64,
    min: usize,
    max: usize,
    ascii_only: bool,
) -> Result<(), IpcSchemaError> {
    text::check(s, min, max, ascii_only).map_err(|v| match v {
        text::TextViolation::BadLength => IpcSchemaError::BadLength { key },
        text::TextViolation::Forbidden => IpcSchemaError::BadText { key },
        text::TextViolation::Unassigned => IpcSchemaError::Unassigned { key },
        text::TextViolation::NotNfc => IpcSchemaError::NotNfc { key },
    })
}

// ---- typed extraction from a scanned Value ----

fn map_entries(v: &Value, n: usize) -> Result<&[(u64, Value)], IpcSchemaError> {
    let Value::Map(entries) = v else {
        return Err(IpcSchemaError::NotMap);
    };
    if entries.len() != n {
        return Err(IpcSchemaError::WrongEntryCount {
            expected: n,
            got: entries.len(),
        });
    }
    for (i, (k, _)) in entries.iter().enumerate() {
        if *k != i as u64 {
            return Err(IpcSchemaError::WrongKey {
                pos: i,
                expected: i as u64,
                got: *k,
            });
        }
    }
    Ok(entries)
}

fn take_uint(v: &Value, key: u64) -> Result<u64, IpcSchemaError> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(IpcSchemaError::WrongType { key }),
    }
}

fn take_bytes_exact<const N: usize>(v: &Value, key: u64) -> Result<[u8; N], IpcSchemaError> {
    match v {
        Value::Bytes(b) if b.len() == N => {
            Ok(<[u8; N]>::try_from(b.as_slice()).expect("len checked"))
        }
        Value::Bytes(_) => Err(IpcSchemaError::BadLength { key }),
        _ => Err(IpcSchemaError::WrongType { key }),
    }
}

fn take_text(v: &Value, key: u64) -> Result<&str, IpcSchemaError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(IpcSchemaError::WrongType { key }),
    }
}

fn take_text_or_null(v: &Value, key: u64) -> Result<Option<&str>, IpcSchemaError> {
    match v {
        Value::Text(s) => Ok(Some(s)),
        Value::Null => Ok(None),
        _ => Err(IpcSchemaError::WrongType { key }),
    }
}

fn expect_message_type(v: &Value, expected: &str) -> Result<(), IpcSchemaError> {
    match take_text(v, 0)? {
        s if s == expected => Ok(()),
        _ => Err(IpcSchemaError::MessageTypeMismatch),
    }
}

fn opt_text_value(o: &Option<String>) -> Value {
    match o {
        Some(s) => Value::Text(s.clone()),
        None => Value::Null,
    }
}

/// Decode a bool carried as a `uint` 0/1.
fn take_bool_uint(v: &Value, key: u64) -> Result<bool, IpcSchemaError> {
    match take_uint(v, key)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(IpcSchemaError::OutOfRange { key }),
    }
}

fn limits(max_total: usize, entries: usize) -> Limits {
    Limits {
        max_total,
        max_depth: 1,
        max_bytes: REQUEST_ID_LEN,
        max_text: MAX_USERNAME.max(MAX_MESSAGE_TYPE),
        max_map_entries: entries,
    }
}

// ---- auth_request.v1 (PAM -> verifier) ----

/// The trusted PAM context. Identity/policy fields (device id/name, TTL, service allowlist) are supplied
/// by the daemon, **not** by this message (ipc-design §3 answer 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub username: String,
    pub pam_service: String,
    pub pam_tty: Option<String>,
    pub pam_rhost: Option<String>,
}

impl AuthRequest {
    pub fn validate(&self) -> Result<(), IpcSchemaError> {
        check_text(&self.username, 1, 1, MAX_USERNAME, false)?;
        check_text(&self.pam_service, 2, 1, MAX_PAM_SERVICE, false)?;
        if let Some(s) = &self.pam_tty {
            check_text(s, 3, 1, MAX_PAM_TTY_RHOST, false)?;
        }
        if let Some(s) = &self.pam_rhost {
            check_text(s, 4, 1, MAX_PAM_TTY_RHOST, false)?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, IpcSchemaError> {
        self.validate()?;
        let entries = vec![
            (0, Value::Text(MT_AUTH_REQUEST.to_string())),
            (1, Value::Text(self.username.clone())),
            (2, Value::Text(self.pam_service.clone())),
            (3, opt_text_value(&self.pam_tty)),
            (4, opt_text_value(&self.pam_rhost)),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcSchemaError> {
        let v = cbor::scan_structure(bytes, limits(AUTH_REQUEST_MAX_TOTAL, 5))?;
        let e = map_entries(&v, 5)?;
        expect_message_type(&e[0].1, MT_AUTH_REQUEST)?;
        let req = AuthRequest {
            username: take_text(&e[1].1, 1)?.to_string(),
            pam_service: take_text(&e[2].1, 2)?.to_string(),
            pam_tty: take_text_or_null(&e[3].1, 3)?.map(str::to_string),
            pam_rhost: take_text_or_null(&e[4].1, 4)?.map(str::to_string),
        };
        req.validate()?;
        Ok(req)
    }
}

// ---- confirmation_code.v1 (verifier -> PAM) ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationCode {
    pub request_id: [u8; 16],
    pub confirmation_code: String,
}

impl ConfirmationCode {
    pub fn validate(&self) -> Result<(), IpcSchemaError> {
        if self.confirmation_code.len() != CONFIRMATION_CODE_LEN
            || !self.confirmation_code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(IpcSchemaError::BadLength { key: 2 });
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, IpcSchemaError> {
        self.validate()?;
        let entries = vec![
            (0, Value::Text(MT_CONFIRMATION_CODE.to_string())),
            (1, Value::Bytes(self.request_id.to_vec())),
            (2, Value::Text(self.confirmation_code.clone())),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcSchemaError> {
        let v = cbor::scan_structure(bytes, limits(SMALL_MSG_MAX_TOTAL, 3))?;
        let e = map_entries(&v, 3)?;
        expect_message_type(&e[0].1, MT_CONFIRMATION_CODE)?;
        let msg = ConfirmationCode {
            request_id: take_bytes_exact::<16>(&e[1].1, 1)?,
            confirmation_code: take_text(&e[2].1, 2)?.to_string(),
        };
        msg.validate()?;
        Ok(msg)
    }
}

// ---- display_ack.v1 (PAM -> verifier) ----

/// `conversation_succeeded` reports that the PAM conversation delivered the code and the user proceeded;
/// it is not a promise the code was actually rendered (ipc-design §4, design §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayAck {
    pub request_id: [u8; 16],
    pub conversation_succeeded: bool,
}

impl DisplayAck {
    pub fn encode(&self) -> Result<Vec<u8>, IpcSchemaError> {
        let entries = vec![
            (0, Value::Text(MT_DISPLAY_ACK.to_string())),
            (1, Value::Bytes(self.request_id.to_vec())),
            (2, Value::Uint(u64::from(self.conversation_succeeded))),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcSchemaError> {
        let v = cbor::scan_structure(bytes, limits(SMALL_MSG_MAX_TOTAL, 3))?;
        let e = map_entries(&v, 3)?;
        expect_message_type(&e[0].1, MT_DISPLAY_ACK)?;
        Ok(DisplayAck {
            request_id: take_bytes_exact::<16>(&e[1].1, 1)?,
            conversation_succeeded: take_bool_uint(&e[2].1, 2)?,
        })
    }
}

// ---- outcome.v1 (verifier -> PAM) ----

/// The bounded auth outcome (ipc-design §4). No free-text reason; the PAM mapping is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeCode {
    Success = 0,
    Denied = 1,
    Unavailable = 2,
    Timeout = 3,
    ProtocolError = 4,
    InternalError = 5,
}

impl OutcomeCode {
    fn from_uint(n: u64) -> Result<Self, IpcSchemaError> {
        Ok(match n {
            0 => OutcomeCode::Success,
            1 => OutcomeCode::Denied,
            2 => OutcomeCode::Unavailable,
            3 => OutcomeCode::Timeout,
            4 => OutcomeCode::ProtocolError,
            5 => OutcomeCode::InternalError,
            _ => return Err(IpcSchemaError::UnknownOutcomeCode),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub request_id: [u8; 16],
    pub result: OutcomeCode,
}

impl Outcome {
    pub fn encode(&self) -> Result<Vec<u8>, IpcSchemaError> {
        let entries = vec![
            (0, Value::Text(MT_OUTCOME.to_string())),
            (1, Value::Bytes(self.request_id.to_vec())),
            (2, Value::Uint(self.result as u64)),
        ];
        Ok(cbor::encode(&Value::Map(entries)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcSchemaError> {
        let v = cbor::scan_structure(bytes, limits(SMALL_MSG_MAX_TOTAL, 3))?;
        let e = map_entries(&v, 3)?;
        expect_message_type(&e[0].1, MT_OUTCOME)?;
        Ok(Outcome {
            request_id: take_bytes_exact::<16>(&e[1].1, 1)?,
            result: OutcomeCode::from_uint(take_uint(&e[2].1, 2)?)?,
        })
    }
}
