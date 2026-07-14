//! bifrauth-ipc — local IPC protocol for BifrAuth (PAM module ↔ verifier, ipc-design.md).
//!
//! This crate is transport/daemon-agnostic: it defines the wire messages ([`wire`]), length-prefixed
//! framing ([`frame`]), the boot-time [`clock`]/[`deadline`] authority, and the [`transport`] port. The
//! connection state machine that ties these to the verifier core lives in `bifrauthd`.

pub mod clock;
pub mod deadline;
pub mod frame;
pub mod transport;
pub mod wire;

pub use clock::{BoottimeClock, Clock};
pub use deadline::{Deadline, OVERALL_DEADLINE_SECS};
pub use frame::{FrameError, MAX_BODY_LEN, SetTimeout, read_message, write_message};
pub use transport::{Transport, TransportError};
pub use wire::{AuthRequest, ConfirmationCode, DisplayAck, IpcSchemaError, Outcome, OutcomeCode};

#[cfg(test)]
mod tests {
    use super::*;
    use bifrauth_proto::cbor::{self, Value};
    use std::cell::Cell;
    use std::rc::Rc;

    const RID: [u8; 16] = [0x11; 16];

    // ---- wire round-trips ----

    #[test]
    fn auth_request_roundtrip_with_and_without_optionals() {
        let full = AuthRequest {
            username: "alice".into(),
            pam_service: "sudo".into(),
            pam_tty: Some("pts/0".into()),
            pam_rhost: Some("host.example".into()),
        };
        assert_eq!(AuthRequest::decode(&full.encode().unwrap()).unwrap(), full);

        let minimal = AuthRequest {
            username: "bob".into(),
            pam_service: "login".into(),
            pam_tty: None,
            pam_rhost: None,
        };
        assert_eq!(
            AuthRequest::decode(&minimal.encode().unwrap()).unwrap(),
            minimal
        );
    }

    #[test]
    fn confirmation_code_roundtrip() {
        let m = ConfirmationCode {
            request_id: RID,
            confirmation_code: "012345".into(),
        };
        assert_eq!(ConfirmationCode::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn display_ack_bool_is_uint_0_or_1() {
        for b in [false, true] {
            let m = DisplayAck {
                request_id: RID,
                conversation_succeeded: b,
            };
            assert_eq!(DisplayAck::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }

    #[test]
    fn outcome_roundtrip_all_codes() {
        for c in [
            OutcomeCode::Success,
            OutcomeCode::Denied,
            OutcomeCode::Unavailable,
            OutcomeCode::Timeout,
            OutcomeCode::ProtocolError,
            OutcomeCode::InternalError,
        ] {
            let m = Outcome {
                request_id: RID,
                result: c,
            };
            assert_eq!(Outcome::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }

    // ---- wire negatives ----

    #[test]
    fn auth_request_rejects_wrong_message_type() {
        let bytes = cbor::encode(&Value::Map(vec![
            (0, Value::Text("bifrauth.ipc.outcome.v1".into())),
            (1, Value::Text("alice".into())),
            (2, Value::Text("sudo".into())),
            (3, Value::Null),
            (4, Value::Null),
        ]));
        assert_eq!(
            AuthRequest::decode(&bytes),
            Err(IpcSchemaError::MessageTypeMismatch)
        );
    }

    #[test]
    fn auth_request_rejects_empty_username_and_oversize() {
        let empty = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_AUTH_REQUEST.into())),
            (1, Value::Text(String::new())),
            (2, Value::Text("sudo".into())),
            (3, Value::Null),
            (4, Value::Null),
        ]));
        assert_eq!(
            AuthRequest::decode(&empty),
            Err(IpcSchemaError::BadLength { key: 1 })
        );

        // 257-byte username exceeds MAX_USERNAME (256). The scanner's per-text bound catches it early
        // (before allocating), so it surfaces as a layer-A TooLarge rather than a schema BadLength.
        let big = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_AUTH_REQUEST.into())),
            (1, Value::Text("a".repeat(257))),
            (2, Value::Text("sudo".into())),
            (3, Value::Null),
            (4, Value::Null),
        ]));
        assert_eq!(
            AuthRequest::decode(&big),
            Err(IpcSchemaError::Cbor(cbor::Error::TooLarge))
        );
    }

    #[test]
    fn auth_request_rejects_non_nfc_and_control() {
        // NFC: decomposed "é" (e + combining acute) is not NFC.
        let non_nfc = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_AUTH_REQUEST.into())),
            (1, Value::Text("e\u{0301}".into())),
            (2, Value::Text("sudo".into())),
            (3, Value::Null),
            (4, Value::Null),
        ]));
        assert_eq!(
            AuthRequest::decode(&non_nfc),
            Err(IpcSchemaError::NotNfc { key: 1 })
        );

        // A C0 control (NUL) in pam_service.
        let ctrl = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_AUTH_REQUEST.into())),
            (1, Value::Text("alice".into())),
            (2, Value::Text("su\u{0000}do".into())),
            (3, Value::Null),
            (4, Value::Null),
        ]));
        assert_eq!(
            AuthRequest::decode(&ctrl),
            Err(IpcSchemaError::BadText { key: 2 })
        );
    }

    #[test]
    fn display_ack_rejects_out_of_range_uint() {
        let bytes = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_DISPLAY_ACK.into())),
            (1, Value::Bytes(RID.to_vec())),
            (2, Value::Uint(2)),
        ]));
        assert_eq!(
            DisplayAck::decode(&bytes),
            Err(IpcSchemaError::OutOfRange { key: 2 })
        );
    }

    #[test]
    fn outcome_rejects_unknown_code() {
        let bytes = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_OUTCOME.into())),
            (1, Value::Bytes(RID.to_vec())),
            (2, Value::Uint(6)),
        ]));
        assert_eq!(
            Outcome::decode(&bytes),
            Err(IpcSchemaError::UnknownOutcomeCode)
        );
    }

    #[test]
    fn confirmation_code_rejects_non_digit_and_wrong_len() {
        let bad = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_CONFIRMATION_CODE.into())),
            (1, Value::Bytes(RID.to_vec())),
            (2, Value::Text("01x345".into())),
        ]));
        assert_eq!(
            ConfirmationCode::decode(&bad),
            Err(IpcSchemaError::BadLength { key: 2 })
        );
    }

    #[test]
    fn wrong_request_id_length_is_rejected() {
        let bytes = cbor::encode(&Value::Map(vec![
            (0, Value::Text(wire::MT_OUTCOME.into())),
            (1, Value::Bytes(vec![0u8; 15])),
            (2, Value::Uint(0)),
        ]));
        assert_eq!(
            Outcome::decode(&bytes),
            Err(IpcSchemaError::BadLength { key: 1 })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected_by_scanner() {
        let mut bytes = Outcome {
            request_id: RID,
            result: OutcomeCode::Success,
        }
        .encode()
        .unwrap();
        bytes.push(0x00);
        assert!(matches!(
            Outcome::decode(&bytes),
            Err(IpcSchemaError::Cbor(_))
        ));
    }

    // ---- deadline ----

    #[derive(Clone)]
    struct MockClock(Rc<Cell<u64>>);
    impl MockClock {
        fn new(ns: u64) -> Self {
            MockClock(Rc::new(Cell::new(ns)))
        }
        fn advance(&self, ns: u64) {
            self.0.set(self.0.get() + ns);
        }
    }
    impl Clock for MockClock {
        fn now_boottime_ns(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn deadline_expires_and_stage_never_extends_overall() {
        let clock = MockClock::new(0);
        let overall = Deadline::overall(&clock); // 30s
        assert!(!overall.is_expired(&clock));
        assert_eq!(overall.remaining(&clock).as_secs(), 30);

        // A 20s stage cap shortens; a 60s stage cap cannot exceed the 30s overall.
        assert_eq!(overall.stage(&clock, 20).remaining(&clock).as_secs(), 20);
        assert_eq!(
            overall.stage(&clock, 60).boottime_ns(),
            overall.boottime_ns()
        );

        clock.advance(30 * 1_000_000_000);
        assert!(overall.is_expired(&clock));
        assert_eq!(overall.remaining(&clock), core::time::Duration::ZERO);
    }
}
