//! The shared `{ ok, error, data }` response envelope from CONTRACTS. Error
//! responses also carry the stable `code` the harness matches on.

use serde_json::{json, Value};

use crate::error::AgentError;

pub fn ok(data: Value) -> Value {
    json!({ "ok": true, "error": Value::Null, "data": data })
}

pub fn fail(e: &AgentError) -> Value {
    json!({
        "ok": false,
        "error": e.message,
        "code": e.code,
        "data": Value::Null,
    })
}
