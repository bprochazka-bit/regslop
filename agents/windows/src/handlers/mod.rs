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
            // A missing or wrong-typed required field is a malformed request
            // (caller error), not an agent bug. CONTRACTS 0.1.4: BAD_REQUEST.
            AgentError::new("BAD_REQUEST", format!("missing or non-string field '{field}'"))
        })
}

/// Like [`req_str`], but for a registry key path. Additionally rejects a path
/// that starts with the `\` separator: CONTRACTS says paths never start with a
/// separator, so a leading separator is a malformed request (BAD_REQUEST), an
/// invalid constant rather than a real not-found. The empty string (the hive
/// root) is allowed. Hive filesystem paths use [`req_str`], not this.
pub fn req_path(body: &Value, field: &str) -> Result<String, AgentError> {
    let p = req_str(body, field)?;
    if p.starts_with('\\') {
        return Err(AgentError::new(
            "BAD_REQUEST",
            format!("path must not start with a separator: '{p}'"),
        ));
    }
    Ok(p)
}

pub fn opt_str(body: &Value, field: &str) -> Option<String> {
    body.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
}

pub fn opt_bool(body: &Value, field: &str, default: bool) -> bool {
    body.get(field).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Resolve the `handle` field to its hive. A missing or non-string `handle` is
/// a malformed request (BAD_REQUEST); a well-formed handle string the agent
/// does not know is HANDLE_INVALID. The harness relies on that split.
pub fn get_hive(state: &AppState, body: &Value) -> Result<Arc<Mutex<Hive>>, AgentError> {
    let handle = req_str(body, "handle")?;
    state
        .registry
        .get(&handle)
        .ok_or_else(|| AgentError::new("HANDLE_INVALID", format!("unknown handle {handle}")))
}

#[cfg(test)]
mod tests {
    use super::{req_path, req_str};
    use serde_json::json;

    #[test]
    fn missing_or_wrong_typed_required_field_is_bad_request() {
        let e = req_str(&json!({}), "path").unwrap_err();
        assert_eq!(e.code, "BAD_REQUEST");
        let e = req_str(&json!({ "path": 123 }), "path").unwrap_err();
        assert_eq!(e.code, "BAD_REQUEST");
    }

    #[test]
    fn req_path_rejects_leading_separator() {
        // Empty (root) and ordinary paths pass.
        assert_eq!(req_path(&json!({ "path": "" }), "path").unwrap(), "");
        assert_eq!(
            req_path(&json!({ "path": "Software\\Foo" }), "path").unwrap(),
            "Software\\Foo"
        );
        // A leading separator is a malformed request.
        let e = req_path(&json!({ "path": "\\Software" }), "path").unwrap_err();
        assert_eq!(e.code, "BAD_REQUEST");
    }
}
