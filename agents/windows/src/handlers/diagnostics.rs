//! Diagnostics endpoints: version handshake, canonical dump, validate.

use serde_json::{json, Value};

use super::get_hive;
use crate::canonical;
use crate::error::AgentError;
use crate::state::AppState;

/// GET /version -> handshake. `protocol` must match the Linux agent's major
/// version or the harness aborts.
pub fn version(state: &AppState) -> Result<Value, AgentError> {
    Ok(json!({
        "agent": "windows",
        "protocol": "0.1.0",
        "backend": state.backend,
    }))
}

/// GET /hive/dump { handle } -> { canonical_json }
pub fn dump(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let canonical_json = canonical::dump_hive(hive.root())?;
    Ok(json!({ "canonical_json": canonical_json }))
}

/// GET /hive/validate { handle } -> { valid, errors, warnings }
///
/// offreg validates the base block and hbin chain implicitly when it loads a
/// hive, so a hive we hold open has already passed those checks. Deep structural
/// invariants (CONTRACTS 1-18) are the harness's structural differ's job; we do
/// not re-derive them from offreg internals we cannot see. We confirm the hive
/// is still enumerable and report that limitation as a warning.
pub fn validate(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();

    // A full canonical walk exercises every key and value; if it succeeds the
    // hive is internally consistent as far as offreg is concerned.
    let walk = canonical::dump_hive(hive.root());
    match walk {
        Ok(_) => Ok(json!({
            "valid": true,
            "errors": [],
            "warnings": [
                "offreg validates structure on load; deep invariants 1-18 are checked by the harness structural differ"
            ],
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "errors": [ e.message ],
            "warnings": [],
        })),
    }
}
