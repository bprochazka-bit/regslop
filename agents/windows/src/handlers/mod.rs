//! HTTP endpoint handlers, one submodule per endpoint group, plus the request
//! dispatcher and shared field-extraction helpers.

pub mod diagnostics;
pub mod hive;
pub mod key;
pub mod security;
pub mod value;

use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::audit;
use crate::error::AgentError;
use crate::offreg::hive::Hive;
use crate::response;
use crate::state::AppState;

/// Route a parsed request to its handler, wrap the result in the response
/// envelope, and append an audit record. `method` is the HTTP method, used to
/// distinguish read vs write on `/key/security` (CONTRACTS 0.1.2).
pub fn dispatch(state: &AppState, method: &str, path: &str, body: &Value) -> Value {
    let result: Result<Value, AgentError> = match path {
        "/version" => diagnostics::version(state),
        "/hive/create" => hive::create(state, body),
        "/hive/load" => hive::load(state, body),
        "/hive/save" => hive::save(state, body),
        "/hive/close" => hive::close(state, body),
        "/hive/checksum" => hive::checksum(state, body),
        "/hive/dump" => diagnostics::dump(state, body),
        "/hive/validate" => diagnostics::validate(state, body),
        "/key/create" => key::create(state, body),
        "/key/delete" => key::delete(state, body),
        "/key/rename" => key::rename(state, body),
        "/key/list" => key::list(state, body),
        "/key/info" => key::info(state, body),
        "/value/set" => value::set(state, body),
        "/value/get" => value::get(state, body),
        "/value/delete" => value::delete(state, body),
        "/key/security" => security::dispatch(state, method, body),
        other => Err(AgentError::new(
            "INTERNAL",
            format!("unknown endpoint {other}"),
        )),
    };

    let resp = match &result {
        Ok(data) => response::ok(data.clone()),
        Err(e) => response::fail(e),
    };
    let (ok, code) = match &result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.code)),
    };
    audit::record(path, body, ok, code);
    resp
}

// --- shared field extraction --------------------------------------------

pub fn req_str(body: &Value, field: &str) -> Result<String, AgentError> {
    body.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            AgentError::new("INTERNAL", format!("missing or non-string field '{field}'"))
        })
}

pub fn opt_str(body: &Value, field: &str) -> Option<String> {
    body.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
}

pub fn opt_bool(body: &Value, field: &str, default: bool) -> bool {
    body.get(field).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Resolve the `handle` field to its hive, returning HANDLE_INVALID on miss.
pub fn get_hive(state: &AppState, body: &Value) -> Result<Arc<Mutex<Hive>>, AgentError> {
    let handle = body
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentError::new("HANDLE_INVALID", "missing handle"))?;
    state
        .registry
        .get(handle)
        .ok_or_else(|| AgentError::new("HANDLE_INVALID", format!("unknown handle {handle}")))
}
