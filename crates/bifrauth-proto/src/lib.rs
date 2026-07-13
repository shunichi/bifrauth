//! bifrauth-proto — BifrAuth のメッセージ表現と canonical CBOR。
//!
//! 規範は `spec/cbor-profile.md`（codex クロスレビュー承認済み）。
//!
//! 公開 API は**層B の検証済みメッセージ**（[`Challenge`] / [`Response`] / [`Envelope`]）の
//! `decode` / `encode` のみ。低レベルの canonical CBOR（層A）は [`cbor`] モジュールに
//! `pub(crate)` で閉じ込め、外部から未検証の `Value` を直接エンコード/受理できないようにする
//! （canonical 生成・受理の契約は schema 層でのみ保証する）。

pub(crate) mod cbor;
pub mod schema;

pub use cbor::Error as CborError;
pub use schema::{Challenge, Envelope, Response, SchemaError};
