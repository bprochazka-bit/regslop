//! Security endpoint: GET and POST /key/security.
//!
//! The protocol uses the same path for read and write, distinguished by HTTP
//! method (CONTRACTS 0.1.2): GET reads (no `sddl` in the request), POST writes
//! (the `sddl` field is REQUIRED). Agents MUST NOT infer the operation from the
//! presence of the `sddl` field. This mirrors agents/windows/src/handlers/security.rs.

use super::{req_str, req_str_allow_empty, Backend};
use crate::error::{AgentError, Result};
use serde_json::{json, Value as J};

pub fn dispatch(backend: &dyn Backend, method: &str, body: &J) -> Result<J> {
    match method {
        "GET" => get(backend, body),
        "POST" => set(backend, body),
        other => Err(AgentError::bad_request(format!(
            "/key/security supports GET (read) and POST (write), not {other}"
        ))),
    }
}

/// GET /key/security { handle, path } -> { sddl }
fn get(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str_allow_empty(body, "handle")?;
    let path = req_str_allow_empty(body, "path")?;
    let sddl = backend.security_get(handle, path)?;
    Ok(json!({ "sddl": sddl }))
}

/// POST /key/security { handle, path, sddl } -> {}
fn set(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str_allow_empty(body, "handle")?;
    let path = req_str_allow_empty(body, "path")?;
    let sddl = req_str(body, "sddl")?;
    backend.security_set(handle, path, sddl)?;
    Ok(json!({}))
}
