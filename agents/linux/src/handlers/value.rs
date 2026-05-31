//! Value endpoints: set, delete, get.

use super::{req_str, req_str_allow_empty, Backend};
use crate::error::{AgentError, Result};
use serde_json::{json, Value as J};

pub fn set(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let key = req_str_allow_empty(body, "key")?;
    // Default value name is "" (CONTRACTS.md), so allow empty.
    let name = req_str_allow_empty(body, "name")?;
    let vtype = req_str(body, "type")?;
    let data = body
        .get("data")
        .ok_or_else(|| AgentError::bad_request("missing field: data"))?;
    backend.value_set(handle, key, name, vtype, data)?;
    Ok(json!({}))
}

pub fn delete(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let key = req_str_allow_empty(body, "key")?;
    let name = req_str_allow_empty(body, "name")?;
    backend.value_delete(handle, key, name)?;
    Ok(json!({}))
}

pub fn get(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let key = req_str_allow_empty(body, "key")?;
    let name = req_str_allow_empty(body, "name")?;
    let v = backend.value_get(handle, key, name)?;
    Ok(json!({ "type": v.vtype, "data": v.data }))
}
