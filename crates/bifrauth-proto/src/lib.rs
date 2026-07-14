//! bifrauth-proto — BifrAuth message representation and canonical CBOR.
//!
//! The normative spec is `spec/cbor-profile.md` (approved via codex cross-review).
//!
//! The application-facing API is the `decode` / `encode` of the **layer-B validated messages**
//! ([`Challenge`] / [`Response`] / [`Envelope`]): application logic only ever handles validated message
//! types, never a raw `Value`.
//!
//! The low-level canonical CBOR (layer A, [`cbor`]) and the shared text policy ([`text`]) are also
//! `pub` as **building blocks for other canonical-CBOR schema authors in this (unpublished) workspace**
//! — notably the local-IPC message schema in `bifrauth-ipc`. Reusing this one scanner and one text
//! policy keeps a single canonical acceptance representation across all message families. An `Ok` from
//! [`cbor::scan_structure`] means only *structural* canonicality; per-field schema validation is the
//! caller's responsibility (as [`schema`] does).

pub mod cbor;
pub mod schema;
pub mod text;
pub(crate) mod unicode_cn;

pub use cbor::Error as CborError;
pub use schema::{Challenge, Envelope, Response, SchemaError};
