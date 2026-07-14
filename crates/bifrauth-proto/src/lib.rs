//! bifrauth-proto — BifrAuth message representation and canonical CBOR.
//!
//! The normative spec is `spec/cbor-profile.md` (approved via codex cross-review).
//!
//! The public API is only the `decode` / `encode` of the **layer-B validated messages**
//! ([`Challenge`] / [`Response`] / [`Envelope`]). The low-level canonical CBOR (layer A) is kept
//! `pub(crate)` inside the [`cbor`] module so callers cannot directly encode/accept an unvalidated
//! `Value` (the canonical generation/acceptance contract is guaranteed only by the schema layer).

pub(crate) mod cbor;
pub mod schema;
pub(crate) mod unicode_cn;

pub use cbor::Error as CborError;
pub use schema::{Challenge, Envelope, Response, SchemaError};
