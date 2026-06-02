//! Shared core for the libreg client utilities (`reg`, `winsc`, `regedit`,
//! `regmount`).
//!
//! This crate links `libreg` directly and drives `libreg::logical::Hive`
//! in process. It provides the pieces every client needs:
//!
//! - [`path`]: parse Windows-style registry paths (root + subpath).
//! - [`mount`]: the mount map that binds predefined roots (HKLM, HKCU, ...)
//!   to offline hive files, so client commands stay syntax compatible with
//!   the Windows tools even though there is no live registry on Linux.
//! - [`identify`]: recognize a hive file and the mount point it belongs at,
//!   by file name and top-level key shape (drives `regmount`).
//! - [`value`]: the REG_* type codec (names, CLI data parsing, display).
//! - [`regfile`]: import and export of the `.reg` text format.
//! - [`sddl`]: convert key security between its binary form and SDDL text.
//! - [`search`]: pattern matching for `reg query /f` searches.
//! - [`session`]: open a hive file, resolve a path inside it, save it back.
//! - [`structure`]: inspect a hive's on-disk format (base block, cell map).
//!
//! The crate has no dependencies beyond `libreg` and the standard library.

pub mod error;
pub mod identify;
pub mod mount;
pub mod path;
pub mod regfile;
pub mod sddl;
pub mod search;
pub mod session;
pub mod structure;
pub mod value;

pub use error::{CliError, CliResult};
