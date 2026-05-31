//! Safe wrappers around offreg.dll.
//!
//! `ffi` holds the raw entry points; `hive` and `key` provide RAII handles.
//! The resolved [`Offreg`] table lives in a process global initialized once at
//! startup by [`init`].

mod ffi;
pub mod hive;
pub mod key;

pub use ffi::*;

use std::sync::OnceLock;

static OFFREG: OnceLock<Offreg> = OnceLock::new();

/// Load offreg.dll and resolve its exports. Call once before serving requests.
pub fn init() -> Result<(), String> {
    let table = Offreg::load()?;
    OFFREG
        .set(table)
        .map_err(|_| "offreg already initialized".to_string())
}

/// Access the resolved offreg entry points. Panics if [`init`] was not called.
pub fn offreg() -> &'static Offreg {
    OFFREG.get().expect("offreg::init was not called")
}
