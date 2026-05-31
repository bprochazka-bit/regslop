//! libreg: a cross-platform Windows Registry hive library.
//!
//! The crate is organised into strict layers (see libreg/CLAUDE.md):
//!
//! - Layer 0 [`format`]: on-disk structures, pure parse/serialize.
//! - Layer 1 `alloc`: cell allocator (not yet implemented).
//! - Layer 2 `logical`: keys, values, security (not yet implemented).
//! - Layer 3 `log`: transaction logs (not yet implemented).
//! - Layer 4 `api`: public surface (not yet implemented).
//!
//! Lower layers must never depend on higher layers. Only `format`'s
//! byte-level parsers may use unsafe code, and none does today.

pub mod format;
