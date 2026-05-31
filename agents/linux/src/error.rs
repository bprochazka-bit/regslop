//! Error type for the Linux agent and its mapping to CONTRACTS.md error codes.
//!
//! The set of codes here is closed: every variant corresponds to a row in the
//! "Error Codes" table of CONTRACTS.md. We do not invent codes. When a real
//! libreg backend lands, its error enum maps into these same strings so the
//! wire contract is unchanged.

use std::fmt;

/// Stable error codes from CONTRACTS.md. The string form is what goes on the
/// wire in the `code` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    HiveNotFound,
    HiveCorrupt,
    HandleInvalid,
    KeyNotFound,
    KeyExists,
    ValueNotFound,
    TypeMismatch,
    AccessDenied,
    // Non-recursive delete of a key that still has subkeys (CONTRACTS 0.1.2).
    // Before 0.1.2 there was no dedicated code and this surfaced as
    // ACCESS_DENIED; the Windows agent surfaced it as INTERNAL. Both now use
    // this code so the harness sees a single, matching error on both sides.
    KeyHasChildren,
    // Reserved for the transaction-log recovery path (recovery tag), not yet
    // reachable from the in-memory backend. Kept to keep the code set closed
    // and aligned with CONTRACTS.md.
    #[allow(dead_code)]
    LogCorrupt,
    Internal,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::HiveNotFound => "HIVE_NOT_FOUND",
            Code::HiveCorrupt => "HIVE_CORRUPT",
            Code::HandleInvalid => "HANDLE_INVALID",
            Code::KeyNotFound => "KEY_NOT_FOUND",
            Code::KeyExists => "KEY_EXISTS",
            Code::ValueNotFound => "VALUE_NOT_FOUND",
            Code::TypeMismatch => "TYPE_MISMATCH",
            Code::AccessDenied => "ACCESS_DENIED",
            Code::KeyHasChildren => "KEY_HAS_CHILDREN",
            Code::LogCorrupt => "LOG_CORRUPT",
            Code::Internal => "INTERNAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentError {
    pub code: Code,
    pub message: String,
}

impl AgentError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        AgentError { code, message: message.into() }
    }

    pub fn handle_invalid(h: &str) -> Self {
        Self::new(Code::HandleInvalid, format!("unknown handle: {h}"))
    }
    pub fn key_not_found(path: &str) -> Self {
        Self::new(Code::KeyNotFound, format!("key path not found: {path}"))
    }
    pub fn key_exists(path: &str) -> Self {
        Self::new(Code::KeyExists, format!("key already exists: {path}"))
    }
    pub fn key_has_children(path: &str) -> Self {
        Self::new(
            Code::KeyHasChildren,
            format!("key has subkeys, pass recursive=true to delete: {path}"),
        )
    }
    pub fn value_not_found(name: &str) -> Self {
        Self::new(Code::ValueNotFound, format!("value not found: {name}"))
    }
    pub fn type_mismatch(msg: impl Into<String>) -> Self {
        Self::new(Code::TypeMismatch, msg)
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        // Malformed requests are caller bugs, mapped to INTERNAL per the table
        // (there is no dedicated BAD_REQUEST code; see spec-questions.md).
        Self::new(Code::Internal, msg)
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AgentError {}

pub type Result<T> = std::result::Result<T, AgentError>;
