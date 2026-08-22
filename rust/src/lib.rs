//! obsign-verify -- re-derive an Obsign receipt's claim, in Rust.
//!
//! READ THIS BEFORE YOU RELY ON IT.
//!
//! **This is a third implementation by the same author, not an independent
//! third-party review.** It cannot discharge the independence claim any more than
//! `js/` can -- programs by one author can share one misreading of a spec, and a third
//! one written by the same hands is a third chance for the same misreading, not an
//! outside opinion. The independent implementation and the commissioned audit
//! (docs/AUDIT_SCOPE.md) are both still open, and what an independent implementation
//! earns is **recognition, not cash**: named on the strangers page, named in the
//! conformance suite, credited in the spec.
//!
//! What it *does* establish is narrower and worth having, and it is different from
//! what the JavaScript port establishes. The JS port tested whether the format
//! survives a language whose native number is a double. This tests something the other
//! two cannot: both of them compute in ARBITRARY-PRECISION integers -- Python's `int`
//! and JavaScript's `BigInt` -- and then narrow to int64 by an explicit `wrap`. A
//! wrapping bug in that shared strategy would be invisible to both. Rust computes in
//! NATIVE i64, where overflow is the machine's own behaviour rather than a step the
//! author remembered to write, and this crate is built with `overflow-checks = true`
//! so an unintended overflow is a panic in testing instead of a silent divergence.
//! Different failure modes on the same spec is the only reason a third implementation
//! is worth anything.
//!
//! It also measured something more useful than agreement: it could not be written from
//! `docs/` alone. Every place the specification ran out is listed in `rust/README.md`,
//! and each one is a latent cross-implementation divergence -- three of which turned
//! out to be real and are recorded there with the receipts that expose them.
//!
//! ZERO DEPENDENCIES, INCLUDING FOR CRYPTOGRAPHY. See `ed25519.rs` for why, and for
//! the honest cost of that choice.

pub mod ed25519;
pub mod graph;
pub mod json;
pub mod replay;
pub mod sha2;
pub mod signature;
pub mod verify;
pub mod witness;

pub const VERSION: &str = "0.3.0";
