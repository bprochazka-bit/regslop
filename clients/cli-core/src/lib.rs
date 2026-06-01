//! Shared core for the libreg client utilities (`reg`, `sc`, `regedit`).
//!
//! This crate links `libreg` directly and drives `libreg::logical::Hive`
//! in process. It provides the pieces every client needs:
//!
//! - [`path`]: parse Windows-style registry paths (root + subpath).
//! - [`mount`]: the mount map that binds predefined roots (HKLM, HKCU, ...)
//!   to offline hive files, so client commands stay syntax compatible with
//!   the Windows tools even though there is no live registry on Linux.
//! - [`value`]: the REG_* type codec (names, CLI data parsing, display).
//! - [`regfile`]: import and export of the `.reg` text format.
//! - [`session`]: open a hive file, resolve a path inside it, save it back.
//!
//! The crate has no dependencies beyond `libreg` and the standard library.

pub mod error;
pub mod mount;
pub mod path;
pub mod regfile;
pub mod session;
pub mod value;

pub use error::{CliError, CliResult};
