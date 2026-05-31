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
    // Structurally malformed request: invalid JSON, a missing or wrong-typed
    // required field, or an unknown constant (unrecognized value-type name, a
    // path starting with a separator). A caller error, not an agent bug
    // (CONTRACTS 0.1.4). Distinct from TYPE_MISMATCH, which is a well-formed
    // request whose `data` does not fit the declared REG type.
    BadRequest,
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
            Code::BadRequest => "BAD_REQUEST",
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
        // Malformed requests are caller errors: CONTRACTS 0.1.4 gives them a
        // dedicated BAD_REQUEST code, distinct from INTERNAL (agent bug).
        Self::new(Code::BadRequest, msg)
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AgentError {}

pub type Result<T> = std::result::Result<T, AgentError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_request_maps_to_contract_code() {
        assert_eq!(Code::BadRequest.as_str(), "BAD_REQUEST");
        // Malformed-request helpers must carry BAD_REQUEST, not INTERNAL, so the
        // harness can tell caller errors from agent bugs (CONTRACTS 0.1.4).
        assert_eq!(AgentError::bad_request("x").code, Code::BadRequest);
    }

    #[test]
    fn each_code_has_a_distinct_wire_string() {
        let codes = [
            Code::HiveNotFound, Code::HiveCorrupt, Code::HandleInvalid,
            Code::KeyNotFound, Code::KeyExists, Code::ValueNotFound,
            Code::TypeMismatch, Code::AccessDenied, Code::BadRequest,
            Code::KeyHasChildren, Code::LogCorrupt, Code::Internal,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in codes {
            assert!(seen.insert(c.as_str()), "duplicate wire string: {}", c.as_str());
        }
    }
}
