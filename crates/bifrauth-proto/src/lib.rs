//! bifrauth-proto — BifrAuth のメッセージ表現と canonical CBOR。
//!
//! 規範は `spec/cbor-profile.md`（codex クロスレビュー承認済み）。
//! - [`cbor`]: 層A（deterministic profile validity）の canonical エンコーダと直接スキャナ。
//! - スキーマ層（層B: challenge.v1 / response.v1 / envelope.v1）は今後追加する。

pub mod cbor;
