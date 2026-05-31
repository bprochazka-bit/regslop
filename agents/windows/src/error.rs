//! Translation from Win32 error DWORDs to the stable CONTRACTS error codes.
//!
//! The harness matches on the `code` field, never on Windows error strings, so
//! every failure path must produce one of the documented codes. The same Win32
//! error means different things by context (a "file not found" from OROpenHive
//! is a missing hive; from OROpenKey it is a missing key), so callers pass the
//! [`Ctx`] in which the call was made.

use crate::winapi::*;

/// The context a failing offreg call was made in, used to disambiguate codes
/// like ERROR_FILE_NOT_FOUND.
#[derive(Clone, Copy)]
pub enum Ctx {
    Hive,
    Key,
    Value,
    Security,
}

#[derive(Debug, Clone)]
pub struct AgentError {
    pub code: &'static str,
    pub message: String,
}

impl AgentError {
    pub fn new(code: &'static str, message: impl Into<String>) -> AgentError {
        AgentError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Map a Win32 error to a CONTRACTS error code given the call context.
pub fn map_win32(err: Dword, ctx: Ctx) -> AgentError {
    let code = match (err, ctx) {
        (ERROR_FILE_NOT_FOUND, Ctx::Hive) | (ERROR_PATH_NOT_FOUND, Ctx::Hive) => "HIVE_NOT_FOUND",
        (ERROR_FILE_NOT_FOUND, Ctx::Value) => "VALUE_NOT_FOUND",
        (ERROR_FILE_NOT_FOUND, _) | (ERROR_PATH_NOT_FOUND, _) => "KEY_NOT_FOUND",
        (ERROR_ACCESS_DENIED, _) => "ACCESS_DENIED",
        (ERROR_INVALID_HANDLE, _) => "HANDLE_INVALID",
        (ERROR_ALREADY_EXISTS, _) => "KEY_EXISTS",
        (ERROR_INVALID_PARAMETER, Ctx::Value) => "TYPE_MISMATCH",
        _ => "INTERNAL",
    };
    AgentError::new(code, format!("offreg returned win32 error {err} ({code})"))
}
