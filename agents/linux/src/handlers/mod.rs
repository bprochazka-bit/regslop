//! HTTP request handlers. Each handler parses parameters from the JSON body,
//! calls the backend, and returns the `data` payload (the envelope is added by
//! `main.rs`). The module layout mirrors agents/windows/src/handlers/ so the
//! two agents stay symmetric: a reviewer can diff file for file.

pub mod diag;
pub mod hive;
pub mod key;
pub mod security;
pub mod value;

use crate::backend::Backend;
use crate::error::{AgentError, Result};
use serde_json::Value as J;

/// Dispatch a request to the right handler. Routing is on path for every
/// endpoint except `/key/security`, where CONTRACTS 0.1.2 distinguishes read
/// (GET) from write (POST) by HTTP method, not by the presence of the `sddl`
/// field. The harness sends the contract method.
pub fn dispatch(backend: &dyn Backend, method: &str, path: &str, body: &J) -> Result<J> {
    match path {
        "/version" => Ok(serde_json::json!({
            "agent": "linux",
            "protocol": crate::canonical::FORMAT_VERSION,
            "backend": backend.backend_id(),
        })),

        "/hive/create" => hive::create(backend, body),
        "/hive/load" => hive::load(backend, body),
        "/hive/save" => hive::save(backend, body),
        "/hive/close" => hive::close(backend, body),

        "/key/create" => key::create(backend, body),
        "/key/delete" => key::delete(backend, body),
        "/key/rename" => key::rename(backend, body),
        "/key/list" => key::list(backend, body),
        "/key/info" => key::info(backend, body),

        "/value/set" => value::set(backend, body),
        "/value/delete" => value::delete(backend, body),
        "/value/get" => value::get(backend, body),

        "/key/security" => security::dispatch(backend, method, body),

        "/hive/dump" => diag::dump(backend, body),
        "/hive/checksum" => diag::checksum(backend, body),
        "/hive/validate" => diag::validate(backend, body),

        other => Err(AgentError::bad_request(format!("unknown endpoint: {other}"))),
    }
}

// --- shared parameter extraction helpers ---

pub(crate) fn req_str<'a>(body: &'a J, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentError::bad_request(format!("missing or non-string field: {key}")))
}

/// A required string field that is allowed to be the empty string (e.g. a key
/// path of "" meaning the hive root, or a default value name "").
pub(crate) fn req_str_allow_empty<'a>(body: &'a J, key: &str) -> Result<&'a str> {
    match body.get(key) {
        Some(J::String(s)) => Ok(s),
        _ => Err(AgentError::bad_request(format!("missing or non-string field: {key}"))),
    }
}

pub(crate) fn opt_bool(body: &J, key: &str, default: bool) -> bool {
    body.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}
